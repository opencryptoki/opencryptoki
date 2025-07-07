/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* Modified for S390 by Robert Burroughs                             */

#include <pthread.h>
#include <string.h>             // for memcmp() et al
#include <strings.h>
#include <stdlib.h>
#include <dlfcn.h>              // for dlopen()
#include <link.h>
#include <errno.h>

#include <openssl/aes.h>

#include "pkcs11types.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"
#include "pkcs_utils.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <ica_api.h>
#pragma GCC diagnostic pop

#ifndef EC_DH
#define NO_EC
#warning "Your Libica does not provide ECC support, use Libica 3.3.0 or newer for ECC."
#endif

#include "tok_specific.h"
#include "tok_struct.h"

#ifndef NO_EC
#include "ec_defs.h"
#include "openssl/obj_mac.h"
#include <openssl/ec.h>
#endif
#include <openssl/crypto.h>
#include <openssl/bn.h>

#define ICA_MAX_MECH_LIST_ENTRIES       153

typedef struct {
    void *libica_dso;
    ica_adapter_handle_t adapter_handle;
    int ica_ec_support_available;
    int ica_ec_keygen_available;
    int ica_ec_signverify_available;
    int ica_ec_derive_available;
    int ica_ec_edwards_support_available;
    int ica_ec_edwards_keygen_available;
    int ica_ec_edwards_signverify_available;
    int ica_ec_montgomery_support_available;
    int ica_ec_montgomery_keygen_available;
    int ica_ec_montgomery_derive_available;
    int ica_rsa_keygen_available;
    int ica_rsa_endecrypt_available;
    int ica_rsa_no_small_pub_exp;
    int ica_p_rng_available;
    int ica_sha1_available;
    int ica_sha2_available;
    int ica_sha512_224_available;
    int ica_sha512_256_available;
    int ica_sha3_available;
    int ica_shake_available;
    int ica_aes_available;
    int ica_new_gcm_available;
    int ica_des_available;
    int ica_des3_available;
    MECH_LIST_ELEMENT mech_list[ICA_MAX_MECH_LIST_ENTRIES];
    CK_ULONG mech_list_len;
} ica_private_data_t;

// Linux really does not need these so we just dummy them up
// so the common code across platforms is usable...
#define KEYTYPE_MODEXPO   1
#define KEYTYPE_PKCSCRT   2

#define MAX_GENERIC_KEY_SIZE 256

const char manuf[] = "IBM";
const char model[] = "ICA";
const char descr[] = "IBM ICA token";
const char label[] = "icatok";

static pthread_mutex_t rngmtx = PTHREAD_MUTEX_INITIALIZER;

#define BIND(dso, sym)  do {                                             \
                            if (p_##sym == NULL)                         \
                                *(void **)(&p_##sym) = dlsym(dso, #sym); \
                        } while (0)

#ifndef NO_EC
typedef ICA_EC_KEY *(*ica_ec_key_new_t) (unsigned int nid,
                                         unsigned int *privlen);
typedef int (*ica_ec_key_init_t) (const unsigned char *X,
                                  const unsigned char *Y,
                                  const unsigned char *D, ICA_EC_KEY *key);
typedef int (*ica_ec_key_generate_t) (ica_adapter_handle_t adapter_handle,
                                      ICA_EC_KEY *key);
typedef int (*ica_ecdh_derive_secret_t) (ica_adapter_handle_t adapter_handle,
                                         const ICA_EC_KEY *privkey_A,
                                         const ICA_EC_KEY *pubkey_B,
                                         unsigned char *z,
                                         unsigned int z_length);
typedef int (*ica_ecdsa_sign_t) (ica_adapter_handle_t adapter_handle,
                                 const ICA_EC_KEY *privkey,
                                 const unsigned char *hash,
                                 unsigned int hash_length,
                                 unsigned char *signature,
                                 unsigned int signature_length);
typedef int (*ica_ecdsa_verify_t) (ica_adapter_handle_t adapter_handle,
                                   const ICA_EC_KEY *pubkey,
                                   const unsigned char *hash,
                                   unsigned int hash_length,
                                   const unsigned char *signature,
                                   unsigned int signature_length);
typedef int (*ica_ec_key_get_public_key_t) (ICA_EC_KEY *key,
                                            unsigned char *q,
                                            unsigned int *q_len);
typedef int (*ica_ec_key_get_private_key_t) (ICA_EC_KEY *key,
                                             unsigned char *d,
                                             unsigned int *d_len);
typedef void (*ica_ec_key_free_t) (ICA_EC_KEY *key);
#endif
typedef void (*ica_cleanup_t) (void);

typedef unsigned int (*ica_aes_xts_ex_t)(const unsigned char *in_data,
                                         unsigned char *out_data,
                                         unsigned long data_length,
                                         unsigned char *key1,
                                         unsigned char *key2,
                                         unsigned int key_length,
                                         unsigned char *tweak,
                                         unsigned char *iv,
                                         unsigned int direction);

typedef void (*ica_allow_external_gcm_iv_in_fips_mode_t)(int allow);

typedef int (*ica_fips_status_t)(void);

#ifndef NO_EC
#ifndef NID_X25519
#define NID_X25519                      1034
#define NID_X448                        1035
#endif
#ifndef NID_ED25519
#define NID_ED25519                     1087
#define NID_ED448                       1088
#endif

#ifndef X25519_KEYGEN
typedef struct ica_x25519_ctx ICA_X25519_CTX;
typedef struct ica_x448_ctx ICA_X448_CTX;
typedef struct ica_ed25519_ctx ICA_ED25519_CTX;
typedef struct ica_ed448_ctx ICA_ED448_CTX;
#endif

typedef int (*ica_x25519_ctx_new_t)(ICA_X25519_CTX **ctx);
typedef int (*ica_x448_ctx_new_t)(ICA_X448_CTX **ctx);
typedef int (*ica_ed25519_ctx_new_t)(ICA_ED25519_CTX **ctx);
typedef int (*ica_ed448_ctx_new_t)(ICA_ED448_CTX **ctx);
typedef int (*ica_x25519_key_set_t)(ICA_X25519_CTX *ctx,
                                    const unsigned char priv[32],
                                    const unsigned char pub[32]);
typedef int (*ica_x448_key_set_t)(ICA_X448_CTX *ctx,
                                  const unsigned char priv[56],
                                  const unsigned char pub[56]);
typedef int (*ica_ed25519_key_set_t)(ICA_ED25519_CTX *ctx,
                                     const unsigned char priv[32],
                                     const unsigned char pub[32]);
typedef int (*ica_ed448_key_set_t)(ICA_ED448_CTX *ctx,
                                   const unsigned char priv[57],
                                   const unsigned char pub[57]);
typedef int (*ica_x25519_key_get_t)(ICA_X25519_CTX *ctx,
                                    unsigned char priv[32],
                                    unsigned char pub[32]);
typedef int (*ica_x448_key_get_t)(ICA_X448_CTX *ctx,
                                  unsigned char priv[56],
                                  unsigned char pub[56]);
typedef int (*ica_ed25519_key_get_t)(ICA_ED25519_CTX *ctx,
                                     unsigned char priv[32],
                                     unsigned char pub[32]);
typedef int (*ica_ed448_key_get_t)(ICA_ED448_CTX *ctx,
                                   unsigned char priv[57],
                                   unsigned char pub[57]);
typedef int (*ica_x25519_key_gen_t)(ICA_X25519_CTX *ctx);
typedef int (*ica_x448_key_gen_t)(ICA_X448_CTX *ctx);
typedef int (*ica_ed25519_key_gen_t)(ICA_ED25519_CTX *ctx);
typedef int (*ica_ed448_key_gen_t)(ICA_ED448_CTX *ctx);
typedef int (*ica_x25519_derive_t)(ICA_X25519_CTX *ctx,
                                   unsigned char shared_secret[32],
                                   const unsigned char peer_pub[32]);
typedef int (*ica_x448_derive_t)(ICA_X448_CTX *ctx,
                                 unsigned char shared_secret[56],
                                 const unsigned char peer_pub[56]);
typedef int (*ica_ed25519_sign_t)(ICA_ED25519_CTX *ctx,
                                  unsigned char sig[64],
                                  const unsigned char *msg, size_t msglen);
typedef int (*ica_ed448_sign_t)(ICA_ED448_CTX *ctx,
                                unsigned char sig[114],
                                const unsigned char *msg, size_t msglen);
typedef int (*ica_ed25519_verify_t)(ICA_ED25519_CTX *ctx,
                                    const unsigned char sig[64],
                                    const unsigned char *msg, size_t msglen);
typedef int (*ica_ed448_verify_t)(ICA_ED448_CTX *ctx,
                                  const unsigned char sig[114],
                                  const unsigned char *msg, size_t msglen);
typedef int (*ica_x25519_ctx_del_t)(ICA_X25519_CTX **ctx);
typedef int (*ica_x448_ctx_del_t)(ICA_X448_CTX **ctx);
typedef int (*ica_ed25519_ctx_del_t)(ICA_ED25519_CTX **ctx);
typedef int (*ica_ed448_ctx_del_t)(ICA_ED448_CTX **ctx);
#endif

/*
 * These symbols loaded from libica via dlsym() can be static, even if
 * multiple instances of the ICA token are used. The libica library loaded
 * via dlopen will return the same symbols when loaded multiple times, but
 * reference counts the library.
 * When unloading the library, dlclose unloads the library only when the
 * reference count of the library is zero. Thus, these symbols are valid until
 * the library got finally unloaded.
 */
#ifndef NO_EC
static ica_ec_key_new_t                p_ica_ec_key_new;
static ica_ec_key_init_t               p_ica_ec_key_init;
static ica_ec_key_generate_t           p_ica_ec_key_generate;
static ica_ecdh_derive_secret_t        p_ica_ecdh_derive_secret;
static ica_ecdsa_sign_t                p_ica_ecdsa_sign;
static ica_ecdsa_verify_t              p_ica_ecdsa_verify;
static ica_ec_key_get_public_key_t     p_ica_ec_key_get_public_key;
static ica_ec_key_get_private_key_t    p_ica_ec_key_get_private_key;
static ica_ec_key_free_t               p_ica_ec_key_free;
#endif
static ica_cleanup_t                   p_ica_cleanup;
static ica_aes_xts_ex_t                p_ica_aes_xts_ex;
static ica_allow_external_gcm_iv_in_fips_mode_t
                                       p_ica_allow_external_gcm_iv_in_fips_mode;
static ica_fips_status_t               p_ica_fips_status;

#ifndef NO_EC
static ica_x25519_ctx_new_t            p_ica_x25519_ctx_new;
static ica_x448_ctx_new_t              p_ica_x448_ctx_new;
static ica_ed25519_ctx_new_t           p_ica_ed25519_ctx_new;
static ica_ed448_ctx_new_t             p_ica_ed448_ctx_new;
static ica_x25519_key_set_t            p_ica_x25519_key_set;
static ica_x448_key_set_t              p_ica_x448_key_set;
static ica_ed25519_key_set_t           p_ica_ed25519_key_set;
static ica_ed448_key_set_t             p_ica_ed448_key_set;
static ica_x25519_key_get_t            p_ica_x25519_key_get;
static ica_x448_key_get_t              p_ica_x448_key_get;
static ica_ed25519_key_get_t           p_ica_ed25519_key_get;
static ica_ed448_key_get_t             p_ica_ed448_key_get;
static ica_x25519_key_gen_t            p_ica_x25519_key_gen;
static ica_x448_key_gen_t              p_ica_x448_key_gen;
static ica_ed25519_key_gen_t           p_ica_ed25519_key_gen;
static ica_ed448_key_gen_t             p_ica_ed448_key_gen;
static ica_x25519_derive_t             p_ica_x25519_derive;
static ica_x448_derive_t               p_ica_x448_derive;
static ica_ed25519_sign_t              p_ica_ed25519_sign;
static ica_ed448_sign_t                p_ica_ed448_sign;
static ica_ed25519_verify_t            p_ica_ed25519_verify;
static ica_ed448_verify_t              p_ica_ed448_verify;
static ica_x25519_ctx_del_t            p_ica_x25519_ctx_del;
static ica_x448_ctx_del_t              p_ica_x448_ctx_del;
static ica_ed25519_ctx_del_t           p_ica_ed25519_ctx_del;
static ica_ed448_ctx_del_t             p_ica_ed448_ctx_del;
#endif

static CK_RV mech_list_ica_initialize(STDLL_TokData_t *tokdata);

#ifndef NO_EC
#define ICATOK_EC_MAX_D_LEN     66      /* secp521 */
#define ICATOK_EC_MAX_Q_LEN     (2*ICATOK_EC_MAX_D_LEN)
#define ICATOK_EC_MAX_SIG_LEN   ICATOK_EC_MAX_Q_LEN
#define ICATOK_EC_MAX_Z_LEN     ICATOK_EC_MAX_D_LEN

static CK_RV ecc_support_in_libica_available(void)
{
    if (p_ica_ec_key_new != NULL &&
        p_ica_ec_key_init != NULL &&
        p_ica_ec_key_generate != NULL &&
        p_ica_ecdh_derive_secret != NULL &&
        p_ica_ecdsa_sign != NULL &&
        p_ica_ecdsa_verify != NULL &&
        p_ica_ec_key_get_public_key != NULL &&
        p_ica_ec_key_get_private_key != NULL &&
        p_ica_ec_key_free != NULL)
        return 1;

    return 0;
}

static CK_RV ecc_edwards_25519_support_in_libica_available(void)
{
    if (p_ica_ed25519_ctx_new != NULL &&
        p_ica_ed25519_key_set != NULL &&
        p_ica_ed25519_key_get != NULL &&
        p_ica_ed25519_key_gen != NULL &&
        p_ica_ed25519_sign != NULL &&
        p_ica_ed25519_verify != NULL &&
        p_ica_ed25519_ctx_del != NULL)
        return 1;

    return 0;
}

static CK_RV ecc_edwards_448_support_in_libica_available(void)
{
    if (p_ica_ed448_ctx_new != NULL &&
        p_ica_ed448_key_set != NULL &&
        p_ica_ed448_key_get != NULL &&
        p_ica_ed448_key_gen != NULL &&
        p_ica_ed448_sign != NULL &&
        p_ica_ed448_verify != NULL &&
        p_ica_ed448_ctx_del != NULL)
        return 1;

    return 0;
}

static CK_RV ecc_montgomery_25519_support_in_libica_available(void)
{
    if (p_ica_x25519_ctx_new != NULL &&
        p_ica_x25519_key_set != NULL &&
        p_ica_x25519_key_get != NULL &&
        p_ica_x25519_key_gen != NULL &&
        p_ica_x25519_derive != NULL &&
        p_ica_x25519_ctx_del != NULL)
        return 1;

    return 0;
}

static CK_RV ecc_montgomery_448_support_in_libica_available(void)
{
    if (p_ica_x448_ctx_new != NULL &&
        p_ica_x448_key_set != NULL &&
        p_ica_x448_key_get != NULL &&
        p_ica_x448_key_gen != NULL &&
        p_ica_x448_derive != NULL &&
        p_ica_x448_ctx_del != NULL)
        return 1;

    return 0;
}

static CK_RV ecc_edwards_support_in_libica_available(void)
{
    return ecc_edwards_25519_support_in_libica_available() &&
           ecc_edwards_448_support_in_libica_available();
}

static CK_RV ecc_montgomery_support_in_libica_available(void)
{
    return ecc_montgomery_25519_support_in_libica_available() &&
           ecc_montgomery_448_support_in_libica_available();
}
#endif

#ifdef SHA512_224
typedef unsigned int (*ica_sha512_224_t)(unsigned int message_part,
                                         unsigned int input_length,
                                         unsigned char *input_data,
                                         sha512_context_t *sha_context,
                                         unsigned char *output_data);

static ica_sha512_224_t                p_ica_sha512_224;
#endif

#ifdef SHA512_256
typedef unsigned int (*ica_sha512_256_t)(unsigned int message_part,
                                         unsigned int input_length,
                                         unsigned char *input_data,
                                         sha512_context_t *sha_context,
                                         unsigned char *output_data);

static ica_sha512_256_t                p_ica_sha512_256;
#endif

#ifdef SHA3_224
typedef unsigned int (*ica_sha3_224_t)(unsigned int message_part,
                                       unsigned int input_length,
                                       unsigned char *input_data,
                                       sha3_224_context_t *sha_context,
                                       unsigned char *output_data);

static ica_sha3_224_t                  p_ica_sha3_224;
#endif

#ifdef SHA3_256
typedef unsigned int (*ica_sha3_256_t)(unsigned int message_part,
                                       unsigned int input_length,
                                       unsigned char *input_data,
                                       sha3_256_context_t *sha_context,
                                       unsigned char *output_data);

static ica_sha3_256_t                  p_ica_sha3_256;
#endif

#ifdef SHA3_384
typedef unsigned int (*ica_sha3_384_t)(unsigned int message_part,
                                       unsigned int input_length,
                                       unsigned char *input_data,
                                       sha3_384_context_t *sha_context,
                                       unsigned char *output_data);

static ica_sha3_384_t                  p_ica_sha3_384;
#endif

#ifdef SHA3_512
typedef unsigned int (*ica_sha3_512_t)(unsigned int message_part,
                                       unsigned int input_length,
                                       unsigned char *input_data,
                                       sha3_512_context_t *sha_context,
                                       unsigned char *output_data);

static ica_sha3_512_t                  p_ica_sha3_512;
#endif

#ifdef SHAKE128
typedef unsigned int (*ica_shake_128_t)(unsigned int message_part,
                                        uint64_t input_length,
                                        const unsigned char *input_data,
                                        shake_128_context_t *shake_128_context,
                                        unsigned char *output_data,
                                        unsigned int output_length);

static ica_shake_128_t                  p_ica_shake_128;
#endif

#ifdef SHAKE256
typedef unsigned int (*ica_shake_256_t)(unsigned int message_part,
                                        uint64_t input_length,
                                        const unsigned char *input_data,
                                        shake_256_context_t *shake_128_context,
                                        unsigned char *output_data,
                                        unsigned int output_length);

static ica_shake_256_t                  p_ica_shake_256;
#endif

#ifndef HAVE_ALT_FIX_FOR_CVE2022_4304
int ossl_bn_rsa_do_unblind(const unsigned char *intermediate,
                           const BIGNUM *unblind,
                           const unsigned char *to_mod,
                           unsigned char *buf, int num,
                           BN_MONT_CTX *m_ctx, BN_ULONG n0);
#endif

struct phdr_cb_data {
    void *handle;
};

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    int j;
    unsigned long start, end;
    struct phdr_cb_data *d = data;
    unsigned long myaddr = (unsigned long)&ica_open_adapter;

    UNUSED(size);

    for (j = 0; j < info->dlpi_phnum; j++) {
        /* Only consider loadable program segments */
        if (info->dlpi_phdr[j].p_type == PT_LOAD) {
            start = info->dlpi_addr + info->dlpi_phdr[j].p_vaddr;
            end = start + info->dlpi_phdr[j].p_memsz;

            if (start <= myaddr && myaddr < end) {
                /* Get library handle of already loaded libica */
                d->handle = dlopen(info->dlpi_name, RTLD_NOW | RTLD_NOLOAD);
                break;
            }
        }
    }
    return 0;
}

static CK_RV load_libica(ica_private_data_t *ica_data)
{
    struct phdr_cb_data data = { .handle = NULL };

    /* Find already loaded libica that it was linked with */
    dl_iterate_phdr(phdr_callback, &data);
    if (data.handle == NULL) {
        TRACE_ERROR("%s: Failed to find libica: %s\n", __func__, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    ica_data->libica_dso = data.handle;

#ifndef NO_EC
    /* Try to resolve all needed functions for ecc support */
    BIND(ica_data->libica_dso, ica_ec_key_new);
    BIND(ica_data->libica_dso, ica_ec_key_init);
    BIND(ica_data->libica_dso, ica_ec_key_generate);
    BIND(ica_data->libica_dso, ica_ecdh_derive_secret);
    BIND(ica_data->libica_dso, ica_ecdsa_sign);
    BIND(ica_data->libica_dso, ica_ecdsa_verify);
    BIND(ica_data->libica_dso, ica_ec_key_get_public_key);
    BIND(ica_data->libica_dso, ica_ec_key_get_private_key);
    BIND(ica_data->libica_dso, ica_ec_key_free);
#endif

#ifdef SHA512_224
    BIND(ica_data->libica_dso, ica_sha512_224);
#endif
#ifdef SHA512_256
    BIND(ica_data->libica_dso, ica_sha512_256);
#endif
#ifdef SHA3_224
    BIND(ica_data->libica_dso, ica_sha3_224);
#endif
#ifdef SHA3_256
    BIND(ica_data->libica_dso, ica_sha3_256);
#endif
#ifdef SHA3_384
    BIND(ica_data->libica_dso, ica_sha3_384);
#endif
#ifdef SHA3_512
    BIND(ica_data->libica_dso, ica_sha3_512);
#endif
#ifdef SHAKE128
    BIND(ica_data->libica_dso, ica_shake_128);
#endif
#ifdef SHAKE256
    BIND(ica_data->libica_dso, ica_shake_256);
#endif

    BIND(ica_data->libica_dso, ica_cleanup);

    BIND(ica_data->libica_dso, ica_aes_xts_ex);

    /*
     * Allow external AES-GCM IV when libica runs in FIPS mode.
     * ica_allow_external_gcm_iv_in_fips_mode() is not always present and only
     * available with newer libraries.
     */
    BIND(ica_data->libica_dso, ica_allow_external_gcm_iv_in_fips_mode);
    if (p_ica_allow_external_gcm_iv_in_fips_mode != NULL)
        p_ica_allow_external_gcm_iv_in_fips_mode(1);

    BIND(ica_data->libica_dso, ica_fips_status);

#ifndef NO_EC
    BIND(ica_data->libica_dso, ica_x25519_ctx_new);
    BIND(ica_data->libica_dso, ica_x448_ctx_new);
    BIND(ica_data->libica_dso, ica_ed25519_ctx_new);
    BIND(ica_data->libica_dso, ica_ed448_ctx_new);
    BIND(ica_data->libica_dso, ica_x25519_key_set);
    BIND(ica_data->libica_dso, ica_x448_key_set);
    BIND(ica_data->libica_dso, ica_ed25519_key_set);
    BIND(ica_data->libica_dso, ica_ed448_key_set);
    BIND(ica_data->libica_dso, ica_x25519_key_get);
    BIND(ica_data->libica_dso, ica_x448_key_get);
    BIND(ica_data->libica_dso, ica_ed25519_key_get);
    BIND(ica_data->libica_dso, ica_ed448_key_get);
    BIND(ica_data->libica_dso, ica_x25519_key_gen);
    BIND(ica_data->libica_dso, ica_x448_key_gen);
    BIND(ica_data->libica_dso, ica_ed25519_key_gen);
    BIND(ica_data->libica_dso, ica_ed448_key_gen);
    BIND(ica_data->libica_dso, ica_x25519_derive);
    BIND(ica_data->libica_dso, ica_x448_derive);
    BIND(ica_data->libica_dso, ica_ed25519_sign);
    BIND(ica_data->libica_dso, ica_ed448_sign);
    BIND(ica_data->libica_dso, ica_ed25519_verify);
    BIND(ica_data->libica_dso, ica_ed448_verify);
    BIND(ica_data->libica_dso, ica_x25519_ctx_del);
    BIND(ica_data->libica_dso, ica_x448_ctx_del);
    BIND(ica_data->libica_dso, ica_ed25519_ctx_del);
    BIND(ica_data->libica_dso, ica_ed448_ctx_del);
#endif

    return CKR_OK;
}

CK_RV token_specific_rng(STDLL_TokData_t *tokdata, CK_BYTE *output,
                         CK_ULONG bytes)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_p_rng_available) {
        if (pthread_mutex_lock(&rngmtx)) {
            TRACE_ERROR("ICA Rng Lock failed.\n");
            return CKR_CANT_LOCK;
        }

        rc = ica_random_number_generate((unsigned int)bytes, output);
        if (rc != 0)
            ica_data->ica_p_rng_available = FALSE;

        pthread_mutex_unlock(&rngmtx);
    }

    if (!ica_data->ica_p_rng_available)
        rc = local_rng(output, bytes);

    return rc;
}

CK_RV token_specific_init(STDLL_TokData_t *tokdata, CK_SLOT_ID SlotNumber,
                          char *conf_name)
{
    ica_private_data_t *ica_data;
    CK_ULONG rc = CKR_OK;

    UNUSED(conf_name);

    ica_data = (ica_private_data_t *)calloc(1, sizeof(ica_private_data_t));
    tokdata->private_data = ica_data;

    rc = load_libica(ica_data);
    if (rc != CKR_OK)
        goto out;

#ifndef NO_EC
    ica_data->ica_ec_support_available = ecc_support_in_libica_available();

    ica_data->ica_ec_edwards_support_available =
                                  ecc_edwards_support_in_libica_available();
    ica_data->ica_ec_montgomery_support_available =
                                  ecc_montgomery_support_in_libica_available();
#endif

    rc = mech_list_ica_initialize(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("mech_list_ica_initialize failed\n");
        goto out;
    }

    rc = ock_generic_filter_mechanism_list(tokdata,
                                           ica_data->mech_list,
                                           ica_data->mech_list_len,
                                           &(tokdata->mech_list),
                                           &(tokdata->mech_list_len));
    if (rc != CKR_OK) {
        TRACE_ERROR("Mechanism filtering failed!  rc = 0x%lx\n", rc);
        return rc;
    }

    TRACE_INFO("ica %s slot=%lu running\n", __func__, SlotNumber);

    rc =  ica_open_adapter(&ica_data->adapter_handle);
    if (rc != 0) {
        TRACE_ERROR("ica_open_adapter failed\n");
        goto out;
    }

out:
    if (rc != CKR_OK) {
        free(ica_data);
        tokdata->private_data = NULL;
    }
    return rc;
}

CK_RV token_specific_final(STDLL_TokData_t *tokdata,
                           CK_BBOOL in_fork_initializer)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;

    TRACE_INFO("ica %s running\n", __func__);
    ica_close_adapter(ica_data->adapter_handle);

    if (p_ica_cleanup != NULL && !in_fork_initializer)
        p_ica_cleanup();
    if (ica_data->libica_dso != NULL && !in_fork_initializer)
        dlclose(ica_data->libica_dso);

    free(tokdata->mech_list);
    free(ica_data);
    tokdata->private_data = NULL;

    return CKR_OK;
}

typedef struct {
    struct openssl_ex_data openssl_ex_data; /* This must be the first field ! */
    ica_rsa_key_mod_expo_t *modexpoKey;
    ica_rsa_key_crt_t *crtKey;
    ICA_EC_KEY *eckey;
    unsigned int ec_privlen;
    void *ed_x_ctx;
    int ed_x_nid;
    BN_BLINDING *blinding;
    BN_MONT_CTX *blinding_mont_ctx;
#ifndef HAVE_ALT_FIX_FOR_CVE2022_4304
    BN_ULONG blinding_mont_ctx_n0;
#endif
} ica_ex_data_t;

void ica_free_ex_data(OBJECT *obj, void *ex_data, size_t ex_data_len)
{
    ica_ex_data_t *data = ex_data;

    if (ex_data == NULL || ex_data_len < sizeof(ica_ex_data_t))
        return;

    if (data->modexpoKey != NULL) {
        free(data->modexpoKey->modulus);
        free(data->modexpoKey->exponent);
        free(data->modexpoKey);
        data->modexpoKey = NULL;
    }

    if (data->crtKey != NULL) {
        free(data->crtKey->p);
        free(data->crtKey->q);
        free(data->crtKey->dp);
        free(data->crtKey->dq);
        free(data->crtKey->qInverse);
        free(data->crtKey);
        data->crtKey = NULL;
    }

    if (data->eckey != NULL) {
        p_ica_ec_key_free(data->eckey);
        data->eckey = NULL;
        data->ec_privlen = 0;
    }

    if (data->blinding != NULL) {
        BN_BLINDING_free(data->blinding);
        data->blinding = NULL;
    }
    if (data->blinding_mont_ctx != NULL) {
        BN_MONT_CTX_free(data->blinding_mont_ctx);
        data->blinding_mont_ctx = NULL;
    }
#ifndef HAVE_ALT_FIX_FOR_CVE2022_4304
    data->blinding_mont_ctx_n0 = 0;
#endif

    openssl_free_ex_data(obj, ex_data, ex_data_len);
}

static CK_BBOOL ica_need_wr_lock_rsa_pubkey(OBJECT *obj, void *ex_data,
                                            size_t ex_data_len)
{
    ica_ex_data_t *data = ex_data;

    UNUSED(obj);

    if (ex_data == NULL || ex_data_len < sizeof(ica_ex_data_t))
        return FALSE;

    return data->modexpoKey == NULL;
}

static CK_BBOOL ica_need_wr_lock_rsa_privkey(OBJECT *obj, void *ex_data,
                                             size_t ex_data_len)
{
    ica_ex_data_t *data = ex_data;

    UNUSED(obj);

    if (ex_data == NULL || ex_data_len < sizeof(ica_ex_data_t))
        return FALSE;

    if (data->blinding == NULL || data->blinding_mont_ctx == NULL)
        return TRUE;

    return data->modexpoKey == NULL && data->crtKey == NULL;
}

static CK_BBOOL ica_need_wr_lock_ec_key(OBJECT *obj, void *ex_data,
                                        size_t ex_data_len)
{
    ica_ex_data_t *data = ex_data;

    UNUSED(obj);

    if (ex_data == NULL || ex_data_len < sizeof(ica_ex_data_t))
        return FALSE;

    return data->eckey == NULL;
}

// count_ones_in_byte: for use in adjust_des_key_parity_bits below
static CK_BYTE count_ones_in_byte(CK_BYTE byte)
{
    CK_BYTE and_mask,           // bit selector
     number_of_ones = 0;

    for (and_mask = 1; and_mask != 0; and_mask <<= 1)   // for each bit,
        if (byte & and_mask)    // if it's a one,
            ++number_of_ones;   // count it

    return number_of_ones;
}

#define EVEN_PARITY TRUE
#define ODD_PARITY FALSE
 // adjust_des_key_parity_bits: to conform to NIST spec for DES and 3DES keys
static void adjust_des_key_parity_bits(CK_BYTE *des_key, CK_ULONG key_size,
                                       CK_BBOOL parity)
{
    CK_ULONG i;

    for (i = 0; i < key_size; i++) // look at each byte in the key
    {
        if ((count_ones_in_byte(des_key[i]) % 2) ^ (parity == ODD_PARITY)) {
            // if parity for this byte isn't what it should be,
            // flip the parity (least significant) bit
            des_key[i] ^= 1;
        }
    }
}

CK_RV token_specific_des_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **des_key, CK_ULONG *len,
                                 CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    UNUSED(tmpl);

    *des_key = malloc(keysize);
    if (*des_key == NULL)
        return CKR_HOST_MEMORY;
    *len = keysize;
    *is_opaque = FALSE;

    // Nothing different to do for DES or TDES here as this is just
    // random data...  Validation handles the rest
    // Only check for weak keys when DES.
    if (keysize == (3 * DES_KEY_SIZE)) {
        rng_generate(tokdata, *des_key, keysize);
        adjust_des_key_parity_bits(*des_key, keysize, ODD_PARITY);
    } else {
        do {
            rng_generate(tokdata, *des_key, keysize);
            adjust_des_key_parity_bits(*des_key, keysize, ODD_PARITY);
        } while (des_check_weak_key(*des_key) == TRUE);
    }


    // we really need to validate the key for parity etc...
    // we should do that here... The caller validates the single des keys
    // against the known and suspected poor keys..<<
    return CKR_OK;
}

CK_RV token_specific_des_ecb(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    if (!ica_data->ica_des_available)
        return openssl_specific_des_ecb(tokdata, in_data, in_data_len,
                                        out_data, out_data_len, key, encrypt);

    /*
     * checks for input and output data length and block sizes
     * are already being carried out in mech_des.c
     * so we skip those
     */

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (encrypt) {
        rc = ica_des_ecb(in_data, out_data, in_data_len, attr->pValue,
                         ICA_ENCRYPT);
    } else {
        rc = ica_des_ecb(in_data, out_data, in_data_len, attr->pValue,
                         ICA_DECRYPT);
    }

    if (rc != 0) {
        rc = CKR_FUNCTION_FAILED;
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
    } else {
        *out_data_len = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_des_cbc(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    if (!ica_data->ica_des_available)
        return openssl_specific_des_cbc(tokdata, in_data, in_data_len,
                                        out_data, out_data_len, key,
                                        init_v, encrypt);

    /*
     * checks for input and output data length and block sizes
     * are already being carried out in mech_des.c
     * so we skip those
     */

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (encrypt) {
        rc = ica_des_cbc(in_data, out_data, in_data_len, attr->pValue, init_v,
                         ICA_ENCRYPT);
    } else {
        rc = ica_des_cbc(in_data, out_data, in_data_len, attr->pValue, init_v,
                         ICA_DECRYPT);
    }
    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    } else {
        *out_data_len = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_tdes_ecb(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE key_value[3 * DES_KEY_SIZE];

    if (!ica_data->ica_des3_available)
        return openssl_specific_tdes_ecb(tokdata, in_data, in_data_len,
                                         out_data, out_data_len, key, encrypt);

    /*
     * checks for input and output data length and block sizes
     * are already being carried out in mech_des3.c
     * so we skip those
     */

    // get the key type
    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return rc;
    }

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    if (keytype == CKK_DES2) {
        memcpy(key_value, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(key_value + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(key_value, attr->pValue, 3 * DES_KEY_SIZE);
    }

    if (encrypt) {
        rc = ica_3des_ecb(in_data, out_data, in_data_len, key_value,
                          ICA_ENCRYPT);
    } else {
        rc = ica_3des_ecb(in_data, out_data, in_data_len, key_value,
                          ICA_DECRYPT);
    }

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    } else {
        *out_data_len = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_tdes_cbc(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE key_value[3 * DES_KEY_SIZE];

    if (!ica_data->ica_des3_available)
        return openssl_specific_tdes_cbc(tokdata, in_data, in_data_len,
                                         out_data, out_data_len, key,
                                         init_v, encrypt);

    /*
     * checks for input and output data length and block sizes
     * are already being carried out in mech_des3.c
     * so we skip those
     */

    // get the key type
    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return rc;
    }

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    if (keytype == CKK_DES2) {
        memcpy(key_value, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(key_value + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(key_value, attr->pValue, 3 * DES_KEY_SIZE);
    }

    if (encrypt) {
        rc = ica_3des_cbc(in_data, out_data, in_data_len, key_value, init_v,
                          ICA_ENCRYPT);
    } else {
        rc = ica_3des_cbc(in_data, out_data, in_data_len, key_value, init_v,
                          ICA_DECRYPT);
    }
    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    } else {
        *out_data_len = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

/*
 *
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 */
CK_RV token_specific_tdes_ofb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                              CK_BYTE *out_data, CK_ULONG data_len,
                              OBJECT *key, CK_BYTE *iv, uint_32 direction)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    if (!ica_data->ica_des3_available)
        return openssl_specific_tdes_ofb(tokdata, in_data, data_len, out_data,
                                         key, iv, direction);

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    rc = ica_3des_ofb(in_data, out_data, (unsigned int) data_len,
                      (unsigned char *) attr->pValue, (unsigned char *) iv,
                      direction);

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

/*
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 */
CK_RV token_specific_tdes_cfb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                              CK_BYTE *out_data, CK_ULONG data_len,
                              OBJECT *key, CK_BYTE *iv, uint_32 cfb_len,
                              uint_32 direction)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    if (!ica_data->ica_des3_available)
        return openssl_specific_tdes_cfb(tokdata, in_data, data_len, out_data,
                                         key, iv, cfb_len, direction);

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    rc = ica_3des_cfb(in_data, out_data, (unsigned int) data_len,
                      (unsigned char *) attr->pValue, (unsigned char *) iv,
                      cfb_len, direction);

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_specific_tdes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                              CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE key_value[3 * DES_KEY_SIZE];

    if (!ica_data->ica_des3_available)
        return openssl_specific_tdes_mac(tokdata, message, message_len,
                                         key, mac);

    // get the key type
    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return rc;
    }

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    if (keytype == CKK_DES2) {
        memcpy(key_value, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(key_value + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(key_value, attr->pValue, 3 * DES_KEY_SIZE);
    }

    rc = ica_3des_cmac_intermediate(message, (unsigned long) message_len,
                                    (unsigned char *) key_value, mac);

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_specific_tdes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                               CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                               CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE key_value[3 * DES_KEY_SIZE];

    if (!ica_data->ica_des3_available)
        return openssl_specific_tdes_cmac(tokdata, message, message_len,
                                          key, mac, first, last, ctx);

    if (key == NULL)
        return CKR_ARGUMENTS_BAD;

    // get the key type
    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return rc;
    }

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    if (keytype == CKK_DES2) {
        memcpy(key_value, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(key_value + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(key_value, attr->pValue, 3 * DES_KEY_SIZE);
    }

    if (first && last) {
        rc = ica_3des_cmac(message, (unsigned long) message_len,
                           mac, DES_BLOCK_SIZE,
                           key_value, ICA_ENCRYPT);
    } else if (!last) {
        rc = ica_3des_cmac_intermediate(message, (unsigned long) message_len,
                                        key_value, mac);
    } else {
        rc = ica_3des_cmac_last(message, (unsigned long) message_len,
                                mac, DES_BLOCK_SIZE,
                                key_value, mac, ICA_ENCRYPT);
    }

    if (rc != 0) {
        TRACE_ERROR("%s: rc: %lu\n", ock_err(ERR_FUNCTION_FAILED), rc);
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

int ica_sha_supported(STDLL_TokData_t *tokdata, CK_MECHANISM_TYPE mech)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;

    switch (mech) {
    case CKM_SHA_1:
        return ica_data->ica_sha1_available;
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
        return ica_data->ica_sha2_available;
    case CKM_SHA512_224:
        return ica_data->ica_sha512_224_available;
    case CKM_SHA512_256:
        return ica_data->ica_sha512_256_available;
    case CKM_SHA3_224:
    case CKM_SHA3_256:
    case CKM_SHA3_384:
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
        return ica_data->ica_sha3_available;
    case CKM_SHAKE_128_KEY_DERIVATION:
    case CKM_SHAKE_256_KEY_DERIVATION:
        return ica_data->ica_shake_available;
    default:
        return FALSE;
    }
}

/*
 * Init SHA data structures
 */
CK_RV token_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                              CK_MECHANISM *mech)
{
    unsigned int ctxsize, devctxsize;
    struct oc_sha_ctx *sc;

    if (!ica_sha_supported(tokdata, mech->mechanism))
        return openssl_specific_sha_init(tokdata, ctx, mech);

    ctxsize = (sizeof(struct oc_sha_ctx) + 0x000F) & ~0x000F;
    switch (mech->mechanism) {
    case CKM_SHA_1:
        devctxsize = sizeof(sha_context_t);
        break;
    case CKM_SHA224:
    case CKM_SHA256:
        devctxsize = sizeof(sha256_context_t);
        break;
    case CKM_SHA384:
    case CKM_SHA512:
#ifdef SHA512_224
    case CKM_SHA512_224:
#endif
#ifdef SHA512_256
    case CKM_SHA512_256:
#endif
        devctxsize = sizeof(sha512_context_t);
        break;
#ifdef SHA3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        devctxsize = sizeof(sha3_224_context_t);
        break;
#endif
#ifdef SHA3_256
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        devctxsize = sizeof(sha3_256_context_t);
        break;
#endif
#ifdef SHA3_384
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        devctxsize = sizeof(sha3_384_context_t);
        break;
#endif
#ifdef SHA3_512
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        devctxsize = sizeof(sha3_512_context_t);
        break;
#endif
    default:
        return CKR_MECHANISM_INVALID;
    }

    /* (re)alloc ctx in one memory area */
    if (ctx->context) {
        free(ctx->context);
        ctx->context_free_func = NULL;
    }
    ctx->context_len = 0;
    ctx->context = malloc(ctxsize + devctxsize);
    if (ctx->context == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    memset(ctx->context, 0, ctxsize + devctxsize);
    ctx->context_len = ctxsize + devctxsize;
    sc = (struct oc_sha_ctx *) ctx->context;
    sc->dev_ctx_offs = ctxsize;

    sc->message_part = SHA_MSG_PART_ONLY;
    switch (mech->mechanism) {
    case CKM_SHA_1:
        sc->hash_len = SHA1_HASH_SIZE;
        sc->hash_blksize = SHA1_BLOCK_SIZE;
        break;
    case CKM_SHA224:
        sc->hash_len = SHA224_HASH_SIZE;
        sc->hash_blksize = SHA224_BLOCK_SIZE;
        break;
    case CKM_SHA256:
        sc->hash_len = SHA256_HASH_SIZE;
        sc->hash_blksize = SHA256_BLOCK_SIZE;
        break;
    case CKM_SHA384:
        sc->hash_len = SHA384_HASH_SIZE;
        sc->hash_blksize = SHA384_BLOCK_SIZE;
        break;
    case CKM_SHA512:
        sc->hash_len = SHA512_HASH_SIZE;
        sc->hash_blksize = SHA512_BLOCK_SIZE;
        break;
#ifdef SHA512_224
    case CKM_SHA512_224:
        sc->hash_len = SHA224_HASH_SIZE;
        sc->hash_blksize = SHA512_BLOCK_SIZE;
        break;
#endif
#ifdef SHA512_256
    case CKM_SHA512_256:
        sc->hash_len = SHA256_HASH_SIZE;
        sc->hash_blksize = SHA512_BLOCK_SIZE;
        break;
#endif
#ifdef SHA3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        sc->hash_len = SHA3_224_HASH_SIZE;
        sc->hash_blksize = SHA3_224_BLOCK_SIZE;
        break;
#endif
#ifdef SHA3_256
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        sc->hash_len = SHA3_256_HASH_SIZE;
        sc->hash_blksize = SHA3_256_BLOCK_SIZE;
        break;
#endif
#ifdef SHA3_384
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        sc->hash_len = SHA3_384_HASH_SIZE;
        sc->hash_blksize = SHA3_384_BLOCK_SIZE;
        break;
#endif
#ifdef SHA3_512
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        sc->hash_len = SHA3_512_HASH_SIZE;
        sc->hash_blksize = SHA3_512_BLOCK_SIZE;
        break;
#endif
    }

    return CKR_OK;
}

CK_RV token_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    int rc;
    CK_RV rv = CKR_OK;
    struct oc_sha_ctx *sc;
    void *dev_ctx;

    if (!ctx)
         return CKR_OPERATION_NOT_INITIALIZED;

    if (!ica_sha_supported(tokdata, ctx->mech.mechanism))
        return openssl_specific_sha(tokdata, ctx, in_data, in_data_len,
                                    out_data, out_data_len);

    if (!ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data || !out_data)
        return CKR_ARGUMENTS_BAD;

    sc = (struct oc_sha_ctx *) ctx->context;
    dev_ctx = ((CK_BYTE *) sc) + sc->dev_ctx_offs;

    if (*out_data_len < sc->hash_len)
        return CKR_BUFFER_TOO_SMALL;

    sc->message_part = SHA_MSG_PART_ONLY;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        {
            sha_context_t *ica_sha_ctx = (sha_context_t *) dev_ctx;
            rc = ica_sha1(sc->message_part, in_data_len,
                          in_data, ica_sha_ctx, sc->hash);
            break;
        }
    case CKM_SHA224:
        {
            sha256_context_t *ica_sha2_ctx = (sha256_context_t *) dev_ctx;
            rc = ica_sha224(sc->message_part, in_data_len,
                            in_data, ica_sha2_ctx, sc->hash);
            break;
        }
    case CKM_SHA256:
        {
            sha256_context_t *ica_sha2_ctx = (sha256_context_t *) dev_ctx;
            rc = ica_sha256(sc->message_part, in_data_len,
                            in_data, ica_sha2_ctx, sc->hash);
            break;
        }
    case CKM_SHA384:
        {
            sha512_context_t *ica_sha3_ctx = (sha512_context_t *) dev_ctx;
            rc = ica_sha384(sc->message_part, in_data_len,
                            in_data, ica_sha3_ctx, sc->hash);
            break;
        }
    case CKM_SHA512:
        {
            sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;
            rc = ica_sha512(sc->message_part, in_data_len,
                            in_data, ica_sha5_ctx, sc->hash);
            break;
        }
#ifdef SHA512_224
    case CKM_SHA512_224:
        {
            sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;

            if (p_ica_sha512_224 == NULL)
                return CKR_MECHANISM_INVALID;

            rc = p_ica_sha512_224(sc->message_part, in_data_len,
                                  in_data, ica_sha5_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA512_256
    case CKM_SHA512_256:
        {
            sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;

            if (p_ica_sha512_256 == NULL)
                 return CKR_MECHANISM_INVALID;

            rc = p_ica_sha512_256(sc->message_part, in_data_len,
                                  in_data, ica_sha5_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        {
            sha3_224_context_t *ica_sha3_ctx = (sha3_224_context_t *) dev_ctx;

            if (p_ica_sha3_224 == NULL)
                 return CKR_MECHANISM_INVALID;

            rc = p_ica_sha3_224(sc->message_part, in_data_len,
                                in_data, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_256
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        {
            sha3_256_context_t *ica_sha3_ctx = (sha3_256_context_t *) dev_ctx;

            if (p_ica_sha3_256 == NULL)
                 return CKR_MECHANISM_INVALID;

            rc = p_ica_sha3_256(sc->message_part, in_data_len,
                                in_data, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_384
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        {
            sha3_384_context_t *ica_sha3_ctx = (sha3_384_context_t *) dev_ctx;

            if (p_ica_sha3_384 == NULL)
                 return CKR_MECHANISM_INVALID;

            rc = p_ica_sha3_384(sc->message_part, in_data_len,
                                in_data, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_512
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        {
            sha3_512_context_t *ica_sha3_ctx = (sha3_512_context_t *) dev_ctx;

            if (p_ica_sha3_512 == NULL)
                 return CKR_MECHANISM_INVALID;

            rc = p_ica_sha3_512(sc->message_part, in_data_len,
                                in_data, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (rc == CKR_OK) {
        memcpy(out_data, sc->hash, sc->hash_len);
        *out_data_len = sc->hash_len;
    } else {
        rv = CKR_FUNCTION_FAILED;
    }

    return rv;
}

static CK_RV ica_sha_call(DIGEST_CONTEXT *ctx, CK_BYTE *data,
                          CK_ULONG data_len)
{
    struct oc_sha_ctx *sc = (struct oc_sha_ctx *) ctx->context;
    void *dev_ctx = ((CK_BYTE *) sc) + sc->dev_ctx_offs;
    CK_RV ret;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        {
            sha_context_t *ica_sha_ctx = (sha_context_t *) dev_ctx;
            if (ica_sha_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = ica_sha1(sc->message_part, data_len, data,
                           ica_sha_ctx, sc->hash);
            break;
        }
    case CKM_SHA224:
        {
            sha256_context_t *ica_sha_ctx = (sha256_context_t *) dev_ctx;
            if (ica_sha_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = ica_sha224(sc->message_part, data_len, data,
                             ica_sha_ctx, sc->hash);
            break;
        }
    case CKM_SHA256:
        {
            sha256_context_t *ica_sha_ctx = (sha256_context_t *) dev_ctx;
            if (ica_sha_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = ica_sha256(sc->message_part, data_len, data,
                             ica_sha_ctx, sc->hash);
            break;
        }
    case CKM_SHA384:
        {
            sha512_context_t *ica_sha_ctx = (sha512_context_t *) dev_ctx;
            if (ica_sha_ctx->runningLengthLow == 0 &&
                ica_sha_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = ica_sha384(sc->message_part, data_len, data,
                             ica_sha_ctx, sc->hash);
            break;
        }
    case CKM_SHA512:
        {
            sha512_context_t *ica_sha_ctx = (sha512_context_t *) dev_ctx;
            if (ica_sha_ctx->runningLengthLow == 0 &&
                ica_sha_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = ica_sha512(sc->message_part, data_len, data,
                             ica_sha_ctx, sc->hash);
            break;
        }
#ifdef SHA512_224
    case CKM_SHA512_224:
        {
            sha512_context_t *ica_sha_ctx = (sha512_context_t *) dev_ctx;

            if (p_ica_sha512_224 == NULL)
                return CKR_MECHANISM_INVALID;

            if (ica_sha_ctx->runningLengthLow == 0 &&
                ica_sha_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = p_ica_sha512_224(sc->message_part, data_len, data,
                                   ica_sha_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA512_256
    case CKM_SHA512_256:
        {
            sha512_context_t *ica_sha_ctx = (sha512_context_t *) dev_ctx;

            if (p_ica_sha512_256 == NULL)
                return CKR_MECHANISM_INVALID;

            if (ica_sha_ctx->runningLengthLow == 0 &&
                ica_sha_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = p_ica_sha512_256(sc->message_part, data_len, data,
                                   ica_sha_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        {
            sha3_224_context_t *ica_sha_ctx = (sha3_224_context_t *) dev_ctx;

            if (p_ica_sha3_224 == NULL)
                return CKR_MECHANISM_INVALID;

            if (ica_sha_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = p_ica_sha3_224(sc->message_part, data_len, data,
                                 ica_sha_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_256
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        {
            sha3_256_context_t *ica_sha_ctx = (sha3_256_context_t *) dev_ctx;

            if (p_ica_sha3_256 == NULL)
                return CKR_MECHANISM_INVALID;

            if (ica_sha_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = p_ica_sha3_256(sc->message_part, data_len, data,
                                 ica_sha_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_384
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        {
            sha3_384_context_t *ica_sha_ctx = (sha3_384_context_t *) dev_ctx;

            if (p_ica_sha3_384 == NULL)
                return CKR_MECHANISM_INVALID;

            if (ica_sha_ctx->runningLengthLow == 0 &&
                ica_sha_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = p_ica_sha3_384(sc->message_part, data_len, data,
                                 ica_sha_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_512
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        {
            sha3_512_context_t *ica_sha_ctx = (sha3_512_context_t *) dev_ctx;

            if (p_ica_sha3_512 == NULL)
                return CKR_MECHANISM_INVALID;

            if (ica_sha_ctx->runningLengthLow == 0 &&
                ica_sha_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_FIRST;
            else
                sc->message_part = SHA_MSG_PART_MIDDLE;
            ret = p_ica_sha3_512(sc->message_part, data_len, data,
                                 ica_sha_ctx, sc->hash);
            break;
        }
#endif
    default:
        return CKR_MECHANISM_INVALID;
    }

    return (ret ? CKR_FUNCTION_FAILED : CKR_OK);
}

CK_RV token_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                CK_BYTE *in_data, CK_ULONG in_data_len)
{
    struct oc_sha_ctx *sc;
    int fill, len, rest, ret;

    if (!ctx)
         return CKR_OPERATION_NOT_INITIALIZED;

    if (!ica_sha_supported(tokdata, ctx->mech.mechanism))
        return openssl_specific_sha_update(tokdata, ctx, in_data, in_data_len);

    if (!ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data_len)
        return CKR_OK;

    if (!in_data)
        return CKR_ARGUMENTS_BAD;

    sc = (struct oc_sha_ctx *) ctx->context;

    /* if less than blocksize, save to context buffer for next time */
    if (sc->tail_len + in_data_len < sc->hash_blksize) {
        memcpy(sc->tail + sc->tail_len, in_data, in_data_len);
        sc->tail_len += in_data_len;
        return CKR_OK;
    }

    /* we have at least one block */

    /* if some leftovers from the last update are available
       copy together one block into the tail buffer and hash it */
    if (sc->tail_len) {
        fill = sc->hash_blksize - sc->tail_len;
        memcpy(sc->tail + sc->tail_len, in_data, fill);

        /* hash blksize bytes from the tail buffer */
        ret = ica_sha_call(ctx, sc->tail, sc->hash_blksize);
        if (ret != CKR_OK)
            return ret;

        /* tail buffer is empty now */
        sc->tail_len = 0;

        /* adjust input data pointer and input data len */
        in_data += fill;
        in_data_len -= fill;

        /* if there is no more data to process, we are done */
        if (!in_data_len)
            return CKR_OK;
    }

    /* The tail buffer is empty now, and in_data_len is > 0.
     * Calculate amount of remaining bytes...
     */
    rest = in_data_len % sc->hash_blksize;

    /* and amount of bytes fitting into hash blocks */
    len = in_data_len - rest;

    /* process the full hash blocks */
    if (len > 0) {
        /* hash len bytes from input starting at the beginning */
        ret = ica_sha_call(ctx, in_data, len);
        if (ret != CKR_OK)
            return ret;

        /* adjust input data pointer */
        in_data += len;
    }

    /* Store remaining bytes into the empty tail buffer */
    if (rest > 0) {
        memcpy(sc->tail, in_data, rest);
        sc->tail_len = rest;
    }

    return CKR_OK;
}

CK_RV token_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    int rc;
    CK_RV rv = CKR_OK;
    struct oc_sha_ctx *sc;
    void *dev_ctx;

    if (!ctx)
         return CKR_OPERATION_NOT_INITIALIZED;

    if (!ica_sha_supported(tokdata, ctx->mech.mechanism))
        return openssl_specific_sha_final(tokdata, ctx, out_data, out_data_len);

    if (!ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!out_data || !out_data_len)
        return CKR_ARGUMENTS_BAD;

    sc = (struct oc_sha_ctx *) ctx->context;
    dev_ctx = ((CK_BYTE *) sc) + sc->dev_ctx_offs;
    sc->message_part = SHA_MSG_PART_FINAL;

    if (*out_data_len < sc->hash_len)
        return CKR_BUFFER_TOO_SMALL;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        {
            sha_context_t *ica_sha1_ctx = (sha_context_t *) dev_ctx;
            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha1_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = ica_sha1(sc->message_part, sc->tail_len,
                          (unsigned char *) sc->tail, ica_sha1_ctx, sc->hash);
            break;
        }
    case CKM_SHA224:
        {
            sha256_context_t *ica_sha2_ctx = (sha256_context_t *) dev_ctx;
            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha2_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = ica_sha224(sc->message_part, sc->tail_len,
                            sc->tail, ica_sha2_ctx, sc->hash);
            break;
        }
    case CKM_SHA256:
        {
            sha256_context_t *ica_sha2_ctx = (sha256_context_t *) dev_ctx;
            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha2_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = ica_sha256(sc->message_part, sc->tail_len,
                            sc->tail, ica_sha2_ctx, sc->hash);
            break;
        }
    case CKM_SHA384:
        {
            sha512_context_t *ica_sha3_ctx = (sha512_context_t *) dev_ctx;
            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha3_ctx->runningLengthLow == 0
                && ica_sha3_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = ica_sha384(sc->message_part, sc->tail_len,
                            sc->tail, ica_sha3_ctx, sc->hash);
            break;
        }
    case CKM_SHA512:
        {
            sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;
            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha5_ctx->runningLengthLow == 0
                && ica_sha5_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = ica_sha512(sc->message_part, sc->tail_len,
                            sc->tail, ica_sha5_ctx, sc->hash);
            break;
        }
#ifdef SHA512_224
    case CKM_SHA512_224:
        {
            sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;

            if (p_ica_sha512_224 == NULL)
                return CKR_MECHANISM_INVALID;

            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha5_ctx->runningLengthLow == 0
                && ica_sha5_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = p_ica_sha512_224(sc->message_part, sc->tail_len,
                                  sc->tail, ica_sha5_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA512_256
    case CKM_SHA512_256:
        {
            sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;

            if (p_ica_sha512_256 == NULL)
                return CKR_MECHANISM_INVALID;

            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha5_ctx->runningLengthLow == 0
                && ica_sha5_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = p_ica_sha512_256(sc->message_part, sc->tail_len,
                                  sc->tail, ica_sha5_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        {
            sha3_224_context_t *ica_sha3_ctx = (sha3_224_context_t *) dev_ctx;

            if (p_ica_sha3_224 == NULL)
                return CKR_MECHANISM_INVALID;

            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha3_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = p_ica_sha3_224(sc->message_part, sc->tail_len,
                                sc->tail, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_256
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        {
            sha3_256_context_t *ica_sha3_ctx = (sha3_256_context_t *) dev_ctx;

            if (p_ica_sha3_256 == NULL)
                return CKR_MECHANISM_INVALID;

            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha3_ctx->runningLength == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = p_ica_sha3_256(sc->message_part, sc->tail_len,
                                sc->tail, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_384
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        {
            sha3_384_context_t *ica_sha3_ctx = (sha3_384_context_t *) dev_ctx;

            if (p_ica_sha3_384 == NULL)
                return CKR_MECHANISM_INVALID;

            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha3_ctx->runningLengthLow == 0
                && ica_sha3_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = p_ica_sha3_384(sc->message_part, sc->tail_len,
                                sc->tail, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
#ifdef SHA3_512
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        {
            sha3_512_context_t *ica_sha3_ctx = (sha3_512_context_t *) dev_ctx;

            if (p_ica_sha3_512 == NULL)
                return CKR_MECHANISM_INVALID;

            /* accommodate multi-part when input was so small
             * that we never got to call into libica until final
             */
            if (ica_sha3_ctx->runningLengthLow == 0
                && ica_sha3_ctx->runningLengthHigh == 0)
                sc->message_part = SHA_MSG_PART_ONLY;
            rc = p_ica_sha3_512(sc->message_part, sc->tail_len,
                                sc->tail, ica_sha3_ctx, sc->hash);
            break;
        }
#endif
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (rc != CKR_OK) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    memcpy(out_data, sc->hash, sc->hash_len);
    *out_data_len = sc->hash_len;

out:
    return rv;
}

static CK_RV ica_specific_shake_key_derive(STDLL_TokData_t *tokdata,
                                           SESSION *sess,
                                           CK_MECHANISM *mech,
                                           OBJECT *base_key_obj,
                                           CK_KEY_TYPE base_key_type,
                                           OBJECT *derived_key_obj,
                                           CK_KEY_TYPE derived_key_type,
                                           CK_ULONG derived_key_len)
{
    CK_ATTRIBUTE *base_key_value = NULL;
    CK_ATTRIBUTE *value_attr = NULL, *vallen_attr = NULL;
    CK_BYTE *derived_key_value = NULL;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(base_key_type);

    rc = template_attribute_get_non_empty(base_key_obj->template,
                                          CKA_VALUE, &base_key_value);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the base key.\n");
        return rc;
    }

    derived_key_value = malloc(derived_key_len);
    if (derived_key_value == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    switch (mech->mechanism) {
    case CKM_SHAKE_128_KEY_DERIVATION:
        {
            shake_128_context_t shake_128_context;

            rc = p_ica_shake_128(SHA_MSG_PART_ONLY,
                                 base_key_value->ulValueLen,
                                 base_key_value->pValue,
                                 &shake_128_context,
                                 derived_key_value, derived_key_len);
            rc = rc != 0 ? CKR_FUNCTION_FAILED : CKR_OK;
        }
        break;
    case CKM_SHAKE_256_KEY_DERIVATION:
        {
            shake_256_context_t shake_256_context;

            rc = p_ica_shake_256(SHA_MSG_PART_ONLY,
                                 base_key_value->ulValueLen,
                                 base_key_value->pValue,
                                 &shake_256_context,
                                 derived_key_value, derived_key_len);
            rc = rc != 0 ? CKR_FUNCTION_FAILED : CKR_OK;
        }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

    if (rc != CKR_OK)
        goto out;

    rc = build_attribute(CKA_VALUE, derived_key_value, derived_key_len,
                         &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build the attribute from CKA_VALUE, rc=0x%lx.\n",
                    rc);
        goto out;
    }

    switch (derived_key_type) {
    case CKK_GENERIC_SECRET:
    case CKK_SHA_1_HMAC:
    case CKK_SHA224_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
    case CKK_SHA3_224_HMAC:
    case CKK_SHA3_256_HMAC:
    case CKK_SHA3_384_HMAC:
    case CKK_SHA3_512_HMAC:
    case CKK_SHA512_224_HMAC:
    case CKK_SHA512_256_HMAC:
    case CKK_AES:
    case CKK_AES_XTS:
        /* Supply CKA_VALUE_LEN since this is required for those key types */
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE*)&derived_key_len,
                             sizeof(derived_key_len), &vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to build the attribute from CKA_VALUE_LEN, "
                        "rc=0x%lx.\n", rc);
            goto out;
        }
        break;
    case CKK_DES:
        if (des_check_weak_key(derived_key_value)) {
            TRACE_ERROR("Derived key is a weak DES key\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
        break;
    default:
        break;
    }

    rc = template_update_attribute(derived_key_obj->template, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto out;
    }
    value_attr = NULL;

    if (vallen_attr != NULL) {
        rc = template_update_attribute(derived_key_obj->template, vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto out;
        }
        vallen_attr = NULL;
    }

out:
    if (derived_key_value != NULL) {
        OPENSSL_cleanse(derived_key_value, derived_key_len);
        free(derived_key_value);
    }

    if (value_attr != NULL)
        free(value_attr);
    if (vallen_attr != NULL)
        free(vallen_attr);

    return rc;
}

CK_RV token_specific_shake_key_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_MECHANISM *mech,
                                      OBJECT *base_key_obj,
                                      CK_KEY_TYPE base_key_type,
                                      OBJECT *derived_key_obj,
                                      CK_KEY_TYPE derived_key_type,
                                      CK_ULONG derived_key_len)
{

    if (!ica_sha_supported(tokdata, mech->mechanism))
        return openssl_specific_shake_key_derive(tokdata, sess, mech,
                                                 base_key_obj, base_key_type,
                                                 derived_key_obj,
                                                 derived_key_type,
                                                 derived_key_len);

    return ica_specific_shake_key_derive(tokdata, sess, mech,
                                         base_key_obj, base_key_type,
                                         derived_key_obj, derived_key_type,
                                         derived_key_len);
}

#ifndef LITE
#define LITE
#endif

/* Creates a libICA modulus+exponent key representation using
 * PKCS#11 attributes
 */
static ica_rsa_key_mod_expo_t *rsa_convert_mod_expo_key(CK_ATTRIBUTE *modulus,
                                                        CK_ATTRIBUTE *mod_bits,
                                                        CK_ATTRIBUTE *exponent)
{
    CK_BYTE *ptr = NULL;
    ica_rsa_key_mod_expo_t *modexpokey = NULL;

    /* We need at least the modulus and a (public|private) exponent */
    if (!modulus || !exponent) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return NULL;
    }

    modexpokey =
        (ica_rsa_key_mod_expo_t *) calloc(1, sizeof(ica_rsa_key_mod_expo_t));
    if (modexpokey == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        goto err;
    }

    /* We can't rely solely on CKA_MODULUS_BITS here since Private Keys
     * using the modulus + private exponent representation may also go
     * through this path. Use modulus length in bytes as key_length if
     * no mod_bits is present */
    if (mod_bits != NULL && mod_bits->ulValueLen == sizeof(CK_ULONG)
        && (*(CK_ULONG *) mod_bits->pValue)) {
        modexpokey->key_length = ((*(CK_ULONG *) mod_bits->pValue) + 7) / 8;
    } else {
        modexpokey->key_length = modulus->ulValueLen;
    }

    /* maybe I'm over-cautious here */
    if ((modulus->ulValueLen > modexpokey->key_length) ||
        (exponent->ulValueLen > modexpokey->key_length)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        goto err;
    }

    modexpokey->modulus = (unsigned char *) calloc(1, modexpokey->key_length);

    if (modexpokey->modulus == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        goto err;
    }

    /* right-justified fields */
    ptr = modexpokey->modulus + modexpokey->key_length - modulus->ulValueLen;
    memcpy(ptr, modulus->pValue, modexpokey->key_length);

    modexpokey->exponent = (unsigned char *) calloc(1, modexpokey->key_length);
    if (modexpokey->exponent == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        goto err;
    }

    ptr = modexpokey->exponent + modexpokey->key_length - exponent->ulValueLen;
    memcpy(ptr, exponent->pValue, exponent->ulValueLen);
    return modexpokey;

err:
    if (modexpokey != NULL) {
        free(modexpokey->modulus);
        free(modexpokey->exponent);
        free(modexpokey);
    }

    return NULL;
}

/* Creates a libICA CRT key representation using
 * PKCS#11 attributes
 */
static ica_rsa_key_crt_t *rsa_convert_crt_key(CK_ATTRIBUTE *modulus,
                                              CK_ATTRIBUTE *prime1,
                                              CK_ATTRIBUTE *prime2,
                                              CK_ATTRIBUTE *exp1,
                                              CK_ATTRIBUTE *exp2,
                                              CK_ATTRIBUTE *coeff)
{
    CK_BYTE *ptr = NULL;
    ica_rsa_key_crt_t *crtkey = NULL;

    /* All the above params are required to build a CRT key
     * that can be used by libICA. Private Keys with modulus
     * and private exponent should use rsa_convert_mod_expo_key() */
    if (!modulus || !prime1 || !prime2 || !exp1 || !exp2 || !coeff) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return NULL;
    } else {
        crtkey = (ica_rsa_key_crt_t *) calloc(1, sizeof(ica_rsa_key_crt_t));
        if (crtkey == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return NULL;
        }
        /* use modulus length in bytes as key_length */
        crtkey->key_length = modulus->ulValueLen;

        /* buffers pointed by p, q, dp, dq and qInverse in struct
         * ica_rsa_key_crt_t must be of size key_length/2 or larger.
         * p, dp and qInverse have an additional 8-byte padding. */

        /* need to allocate the buffers. Also, all fields are
         * right-aligned, thus the use for ptr */

        /* FIXME: if individual components lengths are bigger then
         * what we support in libICA then we're in trouble,
         * but maybe explicitly checking them is being over-zealous? */
        if ((prime1->ulValueLen > ((crtkey->key_length + 1) / 2)) ||
            (prime2->ulValueLen > ((crtkey->key_length + 1) / 2)) ||
            (exp1->ulValueLen > ((crtkey->key_length + 1) / 2)) ||
            (exp2->ulValueLen > ((crtkey->key_length + 1) / 2)) ||
            (coeff->ulValueLen > ((crtkey->key_length + 1) / 2))) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            goto err_crtkey;
        }
        crtkey->p = (unsigned char *)
                                calloc(1, ((crtkey->key_length + 1) / 2) + 8);
        if (crtkey->p == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto err_crtkey;
        }
        ptr = crtkey->p + ((crtkey->key_length + 1) / 2) + 8 -
                                            prime1->ulValueLen;
        memcpy(ptr, prime1->pValue, prime1->ulValueLen);

        crtkey->q = (unsigned char *) calloc(1, (crtkey->key_length + 1) / 2);

        if (crtkey->q == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto err_crtkey;
        }
        ptr = crtkey->q + ((crtkey->key_length + 1) / 2) - prime2->ulValueLen;
        memcpy(ptr, prime2->pValue, prime2->ulValueLen);

        crtkey->dp = (unsigned char *)
                                calloc(1, ((crtkey->key_length + 1) / 2) + 8);
        if (crtkey->dp == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto err_crtkey;
        }
        ptr = crtkey->dp + ((crtkey->key_length + 1) / 2) + 8 -
                                            exp1->ulValueLen;
        memcpy(ptr, exp1->pValue, exp1->ulValueLen);

        crtkey->dq = (unsigned char *) calloc(1, (crtkey->key_length + 1) / 2);
        if (crtkey->dq == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto err_crtkey;
        }
        ptr = crtkey->dq + ((crtkey->key_length + 1) / 2) - exp2->ulValueLen;
        memcpy(ptr, exp2->pValue, exp2->ulValueLen);

        crtkey->qInverse =
            (unsigned char *) calloc(1, ((crtkey->key_length + 1) / 2) + 8);
        if (crtkey->qInverse == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto err_crtkey;
        }
        ptr =
            crtkey->qInverse + ((crtkey->key_length + 1) / 2) + 8 -
                                            coeff->ulValueLen;
        memcpy(ptr, coeff->pValue, coeff->ulValueLen);

        /* If p < q, swap and recalculate now */
        if (ica_rsa_crt_key_check(crtkey) > 1) {
            TRACE_ERROR("ica_rsa_crt_key_check failed\n");
            goto err_crtkey;
        }

        return crtkey;
    }

err_crtkey:
    free(crtkey->p);
    free(crtkey->q);
    free(crtkey->dp);
    free(crtkey->dq);
    free(crtkey->qInverse);
    free(crtkey);

    return NULL;
}

static CK_RV rsa_calc_private_exponent(ica_rsa_key_mod_expo_t *publKey,
                                       ica_rsa_key_crt_t *privKey,
                                       TEMPLATE *priv_tmpl)
{
    BIGNUM *d, *e = NULL, *p = NULL, *q = NULL;
    CK_ATTRIBUTE *attr = NULL;
    int len;
    CK_BYTE *buff = NULL;
    CK_RV rc = CKR_OK;

    d = BN_secure_new();
    e = BN_secure_new();
    p = BN_secure_new();
    q = BN_secure_new();
    if (d == NULL || e == NULL || p == NULL || q == NULL) {
        TRACE_DEVEL("BN_secure_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    /*
     * Calculate ϕ(n) = (p − 1) * (q − 1) = n − p − q + 1.
     * Then d = e ^−1 mod ϕ(n)
     */
    if (BN_bin2bn(publKey->modulus, publKey->key_length, d) == NULL ||
        BN_bin2bn(publKey->exponent, publKey->key_length, e) == NULL ||
        BN_bin2bn(privKey->p + 8, privKey->key_length / 2, p) == NULL ||
        BN_bin2bn(privKey->q, privKey->key_length / 2, q) == NULL) {
        TRACE_DEVEL("BN_bin2bn failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (BN_sub(d, d, p) != 1 ||
        BN_sub(d, d, q) != 1 ||
        BN_add_word(d, 1) != 1 ||
        BN_mod_inverse(d, e, d, NULL) == NULL) {
        TRACE_DEVEL("BN_sub/BN_add_word/BN_mod_inverse failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    len = BN_num_bytes(d);
    buff = calloc(len, 1);
    if (buff == NULL) {
        TRACE_DEVEL("calloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (BN_bn2bin(d, buff) != len) {
        TRACE_DEVEL("BN_bn2bin failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = build_attribute(CKA_PRIVATE_EXPONENT, buff, len, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto done;
    }
    attr = NULL;

done:
    if (d != NULL)
        BN_clear_free(d);
    if (e != NULL)
        BN_clear_free(e);
    if (p != NULL)
        BN_clear_free(p);
    if (q != NULL)
        BN_clear_free(q);
    if (buff != NULL)
        free(buff);
    if (attr != NULL)
        free(attr);

    return rc;
}

//
static CK_RV ica_specific_rsa_keygen(STDLL_TokData_t *tokdata,
                                     TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_ATTRIBUTE *publ_exp = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_ULONG mod_bits;
    CK_BBOOL flag;
    unsigned long tmpsize;
    CK_RV rc;
    ica_rsa_key_mod_expo_t *publKey = NULL;
    ica_rsa_key_crt_t *privKey = NULL;
    unsigned int try = 0;

    rc = template_attribute_get_ulong(publ_tmpl, CKA_MODULUS_BITS, &mod_bits);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE; // should never happen
    }

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_PUBLIC_EXPONENT,
                                          &publ_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }
    // FIXME: is this check really necessary?
    if (mod_bits < 512 || mod_bits > 4096) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        return CKR_KEY_SIZE_RANGE;
    }

    /* libICA replicates the openSSL requirement that the public exponent
     * can't be larger than the size of an unsigned long
     */
    if (publ_exp->ulValueLen > sizeof(unsigned long)) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        return CKR_KEY_SIZE_RANGE;
    }

    /* Build publKey:
     * The buffers in ica_rsa_key_mod_expo_t must be
     * allocated by the caller, with key_length size
     * use calloc() so that memory is zeroed (right alignment) */
    publKey =
        (ica_rsa_key_mod_expo_t *) calloc(1, sizeof(ica_rsa_key_mod_expo_t));
    if (publKey == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    /* key_length is in terms of bytes */
    publKey->key_length = ((mod_bits + 7) / 8);

    publKey->modulus = (unsigned char *) calloc(1, publKey->key_length);
    if (publKey->modulus == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto pubkey_cleanup;
    }

    publKey->exponent = (unsigned char *) calloc(1, publKey->key_length);
    if (publKey->exponent == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto pubkey_cleanup;
    }

    /* Use the provided public exponent:
     * all fields must be right-aligned, so make
     * sure we only use the rightmost part */
    /* We know the pub_exp attribute has it's value in BIG ENDIAN        *
     * byte order, and we're assuming we're on s390(x) which is also     *
     * BIG ENDIAN, so no byte swapping required.                         *
     * FIXME: Will need to fix that if porting for little endian         */
    ptr = publKey->exponent + publKey->key_length - publ_exp->ulValueLen;
    memcpy(ptr, publ_exp->pValue, publ_exp->ulValueLen);

    /* If the public exponent is zero, libica will generate a random one *
     * If it is an even number, then we have a problem. Use ptr to cast  *
     * to unsigned int and check                                         */
    ptr = publKey->exponent + publKey->key_length - sizeof(unsigned long);
    if (*((unsigned long *) ptr) != 0 && *((unsigned long *) ptr) % 2 == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto pubkey_cleanup;
    }

    /* Check if small public exponents are allowed */
    if (ica_data->ica_rsa_no_small_pub_exp &&
        *((unsigned long *) ptr) != 0 &&
        *((unsigned long *) ptr) < 65537) {
        TRACE_ERROR("No small RSA public exponents allowed\n");
        rc = CKR_KEY_SIZE_RANGE;
        goto pubkey_cleanup;
    }

    /* Build privKey:
     * buffers pointed by p, q, dp, dq and qInverse in struct
     * ica_rsa_key_crt_t must be of size key_legth/2 or larger.
     * p, dp and qInverse have an additional 8-byte padding */
    privKey = (ica_rsa_key_crt_t *) calloc(1, sizeof(ica_rsa_key_crt_t));
    if (privKey == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto pubkey_cleanup;
    }

    /* modexpo and crt key lengths are always the same */
    privKey->key_length = publKey->key_length;

    privKey->p = (unsigned char *)
                            calloc(1, ((privKey->key_length + 1) / 2) + 8);
    if (privKey->p == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto privkey_cleanup;
    }

    privKey->q = (unsigned char *) calloc(1, (privKey->key_length + 1) / 2);
    if (privKey->q == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto privkey_cleanup;
    }

    privKey->dp = (unsigned char *)
                            calloc(1, ((privKey->key_length + 1) / 2) + 8);
    if (privKey->dp == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto privkey_cleanup;
    }

    privKey->dq = (unsigned char *) calloc(1, (privKey->key_length + 1) / 2);
    if (privKey->dq == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto privkey_cleanup;
    }

    privKey->qInverse =
        (unsigned char *) calloc(1, ((privKey->key_length + 1) / 2) + 8);
    if (privKey->qInverse == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto privkey_cleanup;
    }

retry:
    try++;
    rc = ica_rsa_key_generate_crt(ica_data->adapter_handle,
                                  (unsigned int) mod_bits, publKey, privKey);
    switch (rc) {
    case 0:
        rc = CKR_OK;
        break;
    case EINVAL:
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto privkey_cleanup;
        break;
    case ENODEV:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto privkey_cleanup;
        break;
    case EPERM:
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        rc = CKR_KEY_SIZE_RANGE;
        goto privkey_cleanup;
        break;
    default:
        TRACE_ERROR("%s (try %u)\n", ock_err(ERR_FUNCTION_FAILED), try);
        rc = CKR_FUNCTION_FAILED;
        if (try <= 10)
            goto retry;
        goto privkey_cleanup;
        break;
    }

    /* Build the PKCS#11 public key */
    // modulus: n
    //
    tmpsize = publKey->key_length;
    ptr = p11_bigint_trim(publKey->modulus, &tmpsize);
    if (tmpsize != publKey->key_length) {
        /* This is bad */
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto privkey_cleanup;
    }
    rc = build_attribute(CKA_MODULUS, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    // public exponent
    //
    tmpsize = publKey->key_length;
    ptr = p11_bigint_trim(publKey->exponent, &tmpsize);
    rc = build_attribute(CKA_PUBLIC_EXPONENT, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;


    // local = TRUE
    //
    flag = TRUE;
    rc = build_attribute(CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    //
    // now, do the private key
    //

    // public exponent: e
    //
    tmpsize = publKey->key_length;
    ptr = p11_bigint_trim(publKey->exponent, &tmpsize);
    rc = build_attribute(CKA_PUBLIC_EXPONENT, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    // modulus: n
    //
    tmpsize = publKey->key_length;
    ptr = p11_bigint_trim(publKey->modulus, &tmpsize);
    if (tmpsize != publKey->key_length) {
        /* This is bad */
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto privkey_cleanup;
    }
    rc = build_attribute(CKA_MODULUS, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    /* Calculate the private exponent and add it */
    rc = rsa_calc_private_exponent(publKey, privKey, priv_tmpl);
    if (rc != CKR_OK) {
        TRACE_ERROR("rsa_calc_private_exponent failed\n");
        goto privkey_cleanup;
    }

    // exponent 1: d mod(p-1)
    //
    tmpsize = (privKey->key_length + 1) / 2;
    ptr = p11_bigint_trim(privKey->dp + 8, &tmpsize);
    rc = build_attribute(CKA_EXPONENT_1, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    // exponent 2: d mod(q-1)
    //
    tmpsize = (privKey->key_length + 1) / 2;
    ptr = p11_bigint_trim(privKey->dq, &tmpsize);
    rc = build_attribute(CKA_EXPONENT_2, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    // prime #1: p
    //
    tmpsize = (privKey->key_length + 1) / 2;
    ptr = p11_bigint_trim(privKey->p + 8, &tmpsize);
    rc = build_attribute(CKA_PRIME_1, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    // prime #2: q
    //
    tmpsize = (privKey->key_length + 1) / 2;
    ptr = p11_bigint_trim(privKey->q, &tmpsize);
    rc = build_attribute(CKA_PRIME_2, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

    // CRT coefficient:  q_inverse mod(p)
    //
    tmpsize = (privKey->key_length + 1) / 2;
    ptr = p11_bigint_trim(privKey->qInverse + 8, &tmpsize);
    rc = build_attribute(CKA_COEFFICIENT, ptr, tmpsize, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto privkey_cleanup;
    }
    rc= template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto privkey_cleanup;
    }
    attr = NULL;

privkey_cleanup:
    free(privKey->p);
    free(privKey->q);
    free(privKey->dp);
    free(privKey->dq);
    free(privKey->qInverse);
    free(privKey);
pubkey_cleanup:
    free(publKey->modulus);
    free(publKey->exponent);
    free(publKey);

    if (attr != NULL)
        free(attr);

    return rc;
}

CK_RV token_specific_rsa_generate_keypair(STDLL_TokData_t *tokdata,
                                          TEMPLATE *publ_tmpl,
                                          TEMPLATE *priv_tmpl)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_rsa_keygen_available) {
        rc = ica_specific_rsa_keygen(tokdata, publ_tmpl, priv_tmpl);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_rsa_keygen_available = FALSE;
    }

    if (!ica_data->ica_rsa_keygen_available)
        rc = openssl_specific_rsa_keygen(publ_tmpl, priv_tmpl);

    if (rc != CKR_OK)
        TRACE_DEVEL("ica/openssl_specific_rsa_keygen failed\n");

    return rc;
}

/*
 * ICA token private data used by mod-expo callback function for generating the
 * blinding factor by BN_BLINDING_create_param() or within BN_BLINDING_update()
 * when a new blinding factor is generated after 32 requests.
 * This variable must be thread local!
 */
static __thread ica_private_data_t *ica_blinding_private_data = NULL;

static int ica_blinding_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                   const BIGNUM *m, BN_CTX *ctx,
                                   BN_MONT_CTX *m_ctx)
{
    ica_private_data_t *ica_data = ica_blinding_private_data;
    ica_rsa_key_mod_expo_t ica_mode_expo;
    unsigned char *buffer, *in, *out;
    size_t size;
    int rc = 0;

    if (ica_data == NULL)
        return 0;

    size = BN_num_bytes(m);
    buffer = calloc(1, 4 * size);
    if (buffer == NULL) {
        TRACE_ERROR("Failed to allocate a buffer for libica mod-expo\n");
        goto out;
    }

    ica_mode_expo.key_length = size;
    ica_mode_expo.modulus = buffer;
    ica_mode_expo.exponent = buffer + size;

    in = buffer + 2 * size;
    out = buffer + 3 * size;

    if (BN_bn2binpad(a, in, size) == -1 ||
        BN_bn2binpad(p, ica_mode_expo.exponent, size) == -1 ||
        BN_bn2binpad(m, ica_mode_expo.modulus, size) == -1) {
        TRACE_ERROR("BN_bn2binpad failed\n");
        goto out;
    }

    rc = ica_rsa_mod_expo(ica_data->adapter_handle, in, &ica_mode_expo, out);
    if (rc != 0) {
        TRACE_ERROR("ica_rsa_mod_expo failed with: %s\n", strerror(rc));
        rc = 0;
        goto out;
    }

    if (BN_bin2bn(out, size, r) == NULL) {
        TRACE_ERROR("BN_bin2bn failed\n");
        goto out;
    }

    rc = 1;

out:
    if (buffer != NULL) {
        OPENSSL_cleanse(buffer, 4 * size);
        free(buffer);
    }

    /* Use software fallback if libica operation failed */
    return rc != 1 ? BN_mod_exp_mont(r, a, p, m, ctx, m_ctx) : 1;
}

#ifndef HAVE_ALT_FIX_FOR_CVE2022_4304

#ifdef SIXTY_FOUR_BIT_LONG
    #define BN_MASK2        (0xffffffffffffffffL)
#endif
#ifdef SIXTY_FOUR_BIT
    #define BN_MASK2        (0xffffffffffffffffLL)
#endif
#ifdef THIRTY_TWO_BIT
    #error "Not supported"
#endif

static CK_RV ica_calc_blinding_mont_ctx_n0(STDLL_TokData_t *tokdata,
                                           ica_ex_data_t *ex_data,
                                           BN_CTX *bn_ctx,
                                           CK_ATTRIBUTE *modulus)
{
    BIGNUM *R = NULL, *Ri = NULL, *tmod = NULL;
    BN_ULONG word;

    UNUSED(tokdata);

    /* Calculate blinding_mont_ctx_n0, BN_MONT_CTX is opaque */
    R = BN_CTX_get(bn_ctx);
    Ri = BN_CTX_get(bn_ctx);
    tmod = BN_CTX_get(bn_ctx);
    if (R == NULL || Ri == NULL || tmod == NULL) {
        TRACE_ERROR("BN_CTX_get failed\n");
        return CKR_FUNCTION_FAILED;
    }

    BN_zero(R);
    if (!BN_set_bit(R, BN_BITS2)) {
        TRACE_ERROR("BN_set_bit failed\n");
        return CKR_FUNCTION_FAILED;
    }

    memcpy(&word, ((CK_BYTE *)modulus->pValue) + modulus->ulValueLen -
                  sizeof(BN_ULONG), sizeof(word));
    if (!BN_set_word(tmod, word)) {
        TRACE_ERROR("BN_set_word failed\n");
        return CKR_FUNCTION_FAILED;
    }

    if (BN_is_one(tmod))
        BN_zero(Ri);
    else if ((BN_mod_inverse(Ri, R, tmod, bn_ctx)) == NULL) {
        TRACE_ERROR("BN_mod_inverse failed\n");
        return CKR_FUNCTION_FAILED;
    }
    if (!BN_lshift(Ri, Ri, BN_BITS2)) {
        TRACE_ERROR("BN_lshift failed\n");
        return CKR_FUNCTION_FAILED;
    }

    if (!BN_is_zero(Ri)) {
        if (!BN_sub_word(Ri, 1)) {
            TRACE_ERROR("BN_sub_word failed\n");
            return CKR_FUNCTION_FAILED;
        }
    } else {
        if (!BN_set_word(Ri, BN_MASK2)) {
            TRACE_ERROR("BN_set_word failed\n");
            return CKR_FUNCTION_FAILED;
        }
    }

    if (!BN_div(Ri, NULL, Ri, tmod, bn_ctx)) {
        TRACE_ERROR("BN_div failed\n");
        return CKR_FUNCTION_FAILED;
    }

    ex_data->blinding_mont_ctx_n0 = BN_get_word(Ri);

    return CKR_OK;
}
#endif

static CK_RV ica_blinding_setup(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                                ica_ex_data_t *ex_data, BN_CTX *bn_ctx)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL;
    CK_RV rc = CKR_OK;
    BIGNUM *n, *e;

    /* Get modulus a BIGNUM */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &modulus);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_MODULUS\n");
        goto done;
    }

    n = BN_CTX_get(bn_ctx);
    if (n == NULL ||
        BN_bin2bn(modulus->pValue, modulus->ulValueLen, n) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for modulus\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Get public exponent a BIGNUM */
    rc = template_attribute_get_non_empty(key_obj->template,
                                          CKA_PUBLIC_EXPONENT, &pub_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_PUBLIC_EXPONENT\n");
        goto done;
    }

    e = BN_CTX_get(bn_ctx);
    if (e == NULL ||
        BN_bin2bn(pub_exp->pValue, pub_exp->ulValueLen, e) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for publ-exponent\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    BN_set_flags(n, BN_FLG_CONSTTIME);

    /* Create Montgomery context */
    ex_data->blinding_mont_ctx = BN_MONT_CTX_new();
    if (ex_data->blinding_mont_ctx == NULL) {
        TRACE_ERROR("BN_MONT_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (BN_MONT_CTX_set(ex_data->blinding_mont_ctx, n, bn_ctx) != 1) {
        TRACE_ERROR("BN_MONT_CTX_set failed\n");
        rc = CKR_FUNCTION_FAILED;
        BN_MONT_CTX_free(ex_data->blinding_mont_ctx);
        ex_data->blinding_mont_ctx = NULL;
        goto done;
    }

#ifndef HAVE_ALT_FIX_FOR_CVE2022_4304
    rc = ica_calc_blinding_mont_ctx_n0(tokdata, ex_data, bn_ctx, modulus);
    if (rc != CKR_OK) {
        TRACE_ERROR("ica_calc_blinding_mont_ctx_n0 failed\n");
        goto done;
    }
#endif

    /*
     * BN_BLINDING_create_param() calls the ica_blinding_bn_mod_exp()
     * callback which needs to know the ICA token private data.
     */
    ica_blinding_private_data = ica_data;

    ex_data->blinding = BN_BLINDING_create_param(NULL, e, n, bn_ctx,
                                                 ica_blinding_bn_mod_exp,
                                                 ex_data->blinding_mont_ctx);
    if (ex_data->blinding == NULL) {
        TRACE_ERROR("BN_BLINDING_create_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        BN_MONT_CTX_free(ex_data->blinding_mont_ctx);
        ex_data->blinding_mont_ctx = NULL;
        goto done;
    }

done:
    return rc;
}

static CK_RV ica_blinding_convert(STDLL_TokData_t *tokdata,
                                  ica_ex_data_t *ex_data, BN_CTX *bn_ctx,
                                  CK_BYTE *in_data, CK_BYTE *out_data,
                                  CK_ULONG data_len, BIGNUM **unblind)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    BIGNUM *bn_data = NULL;
    int ret;

    bn_data = BN_CTX_get(bn_ctx);
    if (bn_data == NULL ||
        BN_bin2bn(in_data, data_len, bn_data) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed\n");
        return CKR_FUNCTION_FAILED;
    }

    *unblind = BN_CTX_get(bn_ctx);
    if (*unblind == NULL) {
        TRACE_ERROR("BN_CTX_get failed for unblind factor\n");
        return CKR_FUNCTION_FAILED;
    }
    BN_set_flags(*unblind, BN_FLG_CONSTTIME);

    if (!BN_BLINDING_lock(ex_data->blinding)) {
        TRACE_ERROR("BN_BLINDING_lock failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /* BN_BLINDING_convert_ex() calls BN_BLINDING_update() which may call
     * BN_BLINDING_create_param() to generate a new blinding factor. This
     * calls the ica_blinding_bn_mod_exp() callback which needs to know
     * the ICA token private data.
     */
    ica_blinding_private_data = ica_data;

    ret = BN_BLINDING_convert_ex(bn_data, *unblind, ex_data->blinding, bn_ctx);
    BN_BLINDING_unlock(ex_data->blinding);
    if(ret != 1) {
        TRACE_ERROR("BN_BLINDING_convert_ex failed\n");
        return CKR_FUNCTION_FAILED;
    }

    if (BN_bn2binpad(bn_data, out_data, data_len) != (int)data_len) {
        TRACE_ERROR("BN_bn2binpad failed\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV ica_blinding_invert(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                                 ica_ex_data_t *ex_data, BN_CTX *bn_ctx,
                                 CK_BYTE *in_data, CK_BYTE *out_data,
                                 CK_ULONG data_len, BIGNUM *unblind)
{
#ifdef HAVE_ALT_FIX_FOR_CVE2022_4304
    int rc;
    BIGNUM *bn_data = NULL;

    UNUSED(tokdata);
    UNUSED(key_obj);

    bn_data = BN_CTX_get(bn_ctx);
    if (bn_data == NULL ||
        BN_bin2bn(in_data, data_len, bn_data) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed\n");
        return CKR_FUNCTION_FAILED;
    }
    BN_set_flags(bn_data, BN_FLG_CONSTTIME);

    /*
     * BN_BLINDING_invert_ex is constant-time since OpenSSL commit
     * https://github.com/openssl/openssl/commit/f06ef1657a3d4322153b26231a7afa3d55724e52
     * "Alternative fix for CVE-2022-4304". Care must be taken that bn_data
     * has flag BN_FLG_CONSTTIME set.
     *
     * Commits for OpenSSL releases:
     * - OpenSSL 1.1.1u:
     *   https://github.com/openssl/openssl/commit/3f499b24f3bcd66db022074f7e8b4f6ee266a3ae
     * - OpenSSL 3.0.9:
     *   https://github.com/openssl/openssl/commit/a00d757d9ca212994625d1a02c81cc5edd27e13b
     * - OpenSSl 3.1.1:
     *   https://github.com/openssl/openssl/commit/550a16247e899363ef973aa08623f9b19bb636fb
     */
    rc = BN_BLINDING_invert_ex(bn_data, unblind, ex_data->blinding, bn_ctx);
    if (rc != 1) {
        TRACE_ERROR("BN_BLINDING_invert_ex failed\n");
        return CKR_FUNCTION_FAILED;
    }

    if (BN_bn2binpad(bn_data, out_data, data_len) != (int)data_len) {
        TRACE_ERROR("BN_bn2binpad failed\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
#else
    CK_ATTRIBUTE *modulus = NULL;
    int rc;

    UNUSED(tokdata);
    UNUSED(bn_ctx);

    /* Get modulus */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &modulus);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_MODULUS\n");
        return rc;
    }

    if (modulus->ulValueLen != data_len) {
        TRACE_ERROR("Size of data is not size of modulus\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = ossl_bn_rsa_do_unblind(in_data, unblind, modulus->pValue,
                                out_data, data_len, ex_data->blinding_mont_ctx,
                                ex_data->blinding_mont_ctx_n0);
    if (rc <= 0) {
        TRACE_ERROR("ossl_bn_rsa_do_unblind failed\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
#endif
}

//
//
static CK_RV ica_specific_rsa_encrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data,
                                      CK_ULONG in_data_len,
                                      CK_BYTE *out_data, OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    ica_ex_data_t *ex_data = NULL;
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *pub_exp = NULL;
    CK_ATTRIBUTE *mod_bits = NULL;
    ica_rsa_key_mod_expo_t *publKey = NULL;
    CK_RV rc;

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(ica_ex_data_t),
                             ica_need_wr_lock_rsa_pubkey, ica_free_ex_data);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->modexpoKey == NULL) {
        /* mech_sra.c:ckm_rsa_encrypt accepts only CKO_PUBLIC_KEY */
        template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                         &modulus);
        template_attribute_get_non_empty(key_obj->template, CKA_MODULUS_BITS,
                                         &mod_bits);
        template_attribute_get_non_empty(key_obj->template, CKA_PUBLIC_EXPONENT,
                                         &pub_exp);

        ex_data->modexpoKey = rsa_convert_mod_expo_key(modulus, mod_bits,
                                                       pub_exp);
        if (ex_data->modexpoKey == NULL) {
            TRACE_ERROR("rsa_convert_mod_expo_key failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }
    publKey = ex_data->modexpoKey;

    /* in_data must be in big endian format. 'in_data' size in bits must not
     * exceed the bit length of the key, and size in bytes must
     * be of the same length of the key */
    // FIXME: we're not cheking the size in bits of in_data - but how could we?
    if (publKey->key_length != in_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }
    rc = ica_rsa_mod_expo(ica_data->adapter_handle, in_data, publKey, out_data);
    switch (rc) {
    case 0:
        rc = CKR_OK;
        break;
    case EINVAL:
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        break;
    case ENODEV:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        break;
    case EPERM:
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        rc = CKR_KEY_SIZE_RANGE;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        break;
    }

done:
    object_ex_data_unlock(key_obj);

    return rc;
}

//
//
static CK_RV ica_specific_rsa_decrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data,
                                      CK_ULONG in_data_len,
                                      CK_BYTE *out_data, OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    ica_ex_data_t *ex_data = NULL;
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *prime1 = NULL;
    CK_ATTRIBUTE *prime2 = NULL;
    CK_ATTRIBUTE *exp1 = NULL;
    CK_ATTRIBUTE *exp2 = NULL;
    CK_ATTRIBUTE *coeff = NULL;
    CK_ATTRIBUTE *priv_exp = NULL;
    ica_rsa_key_crt_t *crtKey = NULL;
    ica_rsa_key_mod_expo_t *modexpoKey = NULL;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *unblind = NULL;
    unsigned char *buff = NULL;
    CK_RV rc;

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(ica_ex_data_t),
                             ica_need_wr_lock_rsa_privkey, ica_free_ex_data);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->modexpoKey == NULL && ex_data->crtKey == NULL) {
        /* mech_rsa.c:ckm_rsa_decrypt accepts only CKO_PRIVATE_KEY,
         * but Private Key can have 2 representations (see PKCS#1):
         *  - Modulus + private exponent
         *  - p, q, dp, dq and qInv (CRT format)
         * The former should use ica_rsa_key_mod_expo_t and the latter
         * ica_rsa_key_crt_t. Detect what representation this
         * key_obj has and use the proper convert function */

        template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                         &modulus);
        template_attribute_get_non_empty(key_obj->template,
                                         CKA_PRIVATE_EXPONENT, &priv_exp);
        template_attribute_get_non_empty(key_obj->template, CKA_PRIME_1,
                                         &prime1);
        template_attribute_get_non_empty(key_obj->template, CKA_PRIME_2,
                                         &prime2);
        template_attribute_get_non_empty(key_obj->template, CKA_EXPONENT_1,
                                         &exp1);
        template_attribute_get_non_empty(key_obj->template, CKA_EXPONENT_2,
                                         &exp2);
        template_attribute_get_non_empty(key_obj->template, CKA_COEFFICIENT,
                                         &coeff);

        /* Need to check for CRT Key format *BEFORE* check for mod_expo key,
         * that's because opencryptoki *HAS* a CKA_PRIVATE_EXPONENT attribute
         * even in CRT keys (but with zero length) */

        if (modulus && prime1 && prime2 && exp1 && exp2 && coeff) {
            /* ica_rsa_key_crt_t representation */
            ex_data->crtKey = rsa_convert_crt_key(modulus, prime1, prime2,
                                                  exp1, exp2, coeff);
            if (ex_data->crtKey == NULL) {
                TRACE_ERROR("rsa_convert_crt_key failed\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            /* same check as above */
            if (ex_data->crtKey->key_length != in_data_len) {
                TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
                rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
                goto done;
            }
        } else if (modulus && priv_exp) {
            /* ica_rsa_key_mod_expo_t representation */
            ex_data->modexpoKey = rsa_convert_mod_expo_key(modulus, NULL,
                                                           priv_exp);
            if (ex_data->modexpoKey == NULL) {
                TRACE_ERROR("rsa_convert_mod_expo_key failed\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            /* in_data must be in big endian format. Size in bits must not
             * exceed the bit length of the key, and size in bytes must
             * be the same */
            if (ex_data->modexpoKey->key_length != in_data_len) {
                TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
                rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
                goto done;
            }
        } else {
            /* should never happen */
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
    }

    crtKey = ex_data->crtKey;
    modexpoKey = ex_data->modexpoKey;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        TRACE_ERROR("BN_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (ex_data->blinding == NULL || ex_data->blinding_mont_ctx == NULL) {
        rc = ica_blinding_setup(tokdata, key_obj, ex_data, bn_ctx);
        if (rc != CKR_OK) {
            TRACE_ERROR("ica_blinding_setup failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    buff = malloc(in_data_len * 2);
    if (buff == NULL) {
        TRACE_ERROR("Failed to allocate blinding buffer\n");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = ica_blinding_convert(tokdata, ex_data, bn_ctx, in_data, buff,
                              in_data_len, &unblind);
    if (rc != CKR_OK) {
        TRACE_ERROR("ica_blinding_convert\n");
        goto done;
    }

    if (crtKey != NULL) {
        rc = ica_rsa_crt(ica_data->adapter_handle, buff, crtKey,
                         buff + in_data_len);
    } else {
        rc = ica_rsa_mod_expo(ica_data->adapter_handle, buff, modexpoKey,
                              buff + in_data_len);
    }
    switch (rc) {
    case 0:
        rc = CKR_OK;
        break;
    case EINVAL:
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        break;
    case ENODEV:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        break;
    case EPERM:
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        rc = CKR_KEY_SIZE_RANGE;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        break;
    }
    if (rc != CKR_OK)
        goto done;

    rc = ica_blinding_invert(tokdata, key_obj, ex_data, bn_ctx,
                             buff + in_data_len, out_data, in_data_len,
                             unblind);
    if (rc != CKR_OK) {
        TRACE_ERROR("ica_blinding_invert\n");
        goto done;
    }

done:
    object_ex_data_unlock(key_obj);

    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);
    if (buff != NULL) {
        OPENSSL_cleanse(buff, in_data_len * 2);
        free(buff);
    }

    return rc;
}

static CK_RV os_specific_rsa_encrypt(STDLL_TokData_t *tokdata,
                                     CK_BYTE *in_data,
                                     CK_ULONG in_data_len,
                                     CK_BYTE *out_data, OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_rsa_endecrypt_available) {
        rc = ica_specific_rsa_encrypt(tokdata, in_data, in_data_len,
                                      out_data, key_obj);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_rsa_endecrypt_available = FALSE;
    }

    if (!ica_data->ica_rsa_endecrypt_available)
        rc = openssl_specific_rsa_encrypt(tokdata, in_data, in_data_len,
                                          out_data, key_obj);

    return rc;
}

static CK_RV os_specific_rsa_decrypt(STDLL_TokData_t *tokdata,
                                     CK_BYTE *in_data,
                                     CK_ULONG in_data_len,
                                     CK_BYTE *out_data, OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_rsa_endecrypt_available) {
        rc = ica_specific_rsa_decrypt(tokdata, in_data, in_data_len,
                                      out_data, key_obj);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_rsa_endecrypt_available = FALSE;
    }

    if (!ica_data->ica_rsa_endecrypt_available)
        rc = openssl_specific_rsa_decrypt(tokdata, in_data, in_data_len,
                                          out_data, key_obj);

    return rc;

}

static CK_BBOOL save_data_in_context(CK_BYTE *in_data, CK_ULONG in_data_len,
                                     CK_ULONG tag_data_len,
                                     AES_GCM_CONTEXT *context, CK_BYTE encrypt,
                                     CK_ULONG total, CK_ULONG *remain)
{
    if (encrypt) {
        *remain = (total % AES_BLOCK_SIZE);
        if (total < AES_BLOCK_SIZE) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
            return CK_TRUE;
        }
    } else {
        /* decrypt */
        *remain = ((total - tag_data_len) % AES_BLOCK_SIZE) + tag_data_len;
        if (total < AES_BLOCK_SIZE + tag_data_len) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
            return CK_TRUE;
        }
    }

    return CK_FALSE;
}

#ifdef AES_GCM_KMA
static void new_gcm_specific_aes_gcm_free(STDLL_TokData_t *tokdata,
                                          struct _SESSION *sess,
                                          CK_BYTE *context,
                                          CK_ULONG context_len)
{
    AES_GCM_CONTEXT *ctx = (AES_GCM_CONTEXT *)context;

    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);

    if (ctx == NULL)
        return;

    if ((kma_ctx *)ctx->ulClen != NULL)
        ica_aes_gcm_kma_ctx_free((kma_ctx *)ctx->ulClen);

    free(context);
}

CK_RV new_gcm_specific_aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                    ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
                                    CK_BYTE *key_value, CK_ULONG key_len,
                                    CK_BYTE encrypt)
{
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    AES_GCM_CONTEXT *context = NULL;
    kma_ctx *gcm_ctx;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);

    /* allocate libica gcm context for KMA instruction */
    gcm_ctx = ica_aes_gcm_kma_ctx_new();
    if (!gcm_ctx)
        return CKR_HOST_MEMORY;

    /* initialize gcm context */
    aes_gcm_param = (CK_GCM_PARAMS *)mech->pParameter;
    rc = ica_aes_gcm_kma_init(encrypt, aes_gcm_param->pIv, aes_gcm_param->ulIvLen,
                              key_value, key_len, gcm_ctx);
    if (rc != 0) {
        TRACE_ERROR("ica_aes_gcm_kma_init failed, rc=%ld.\n",rc);
        ica_aes_gcm_kma_ctx_free(gcm_ctx);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* set new ica gcm context in ENCR_DECR_CONTEXT, mis-use ulClen field */
    context = (AES_GCM_CONTEXT *)ctx->context;
    context->ulClen = (CK_ULONG)gcm_ctx;
    ctx->state_unsaveable = CK_TRUE;
    ctx->context_free_func = new_gcm_specific_aes_gcm_free;

done:

    return rc;
}

CK_RV new_gcm_specific_aes_gcm(STDLL_TokData_t *tokdata, SESSION *sess,
                               ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                               CK_ULONG in_data_len, CK_BYTE *out_data,
                               CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    kma_ctx *gcm_ctx = NULL;
    CK_BYTE *tag_data, *auth_data;
    CK_ULONG auth_data_len, tag_data_len;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);

    context = (AES_GCM_CONTEXT *)ctx->context;
    gcm_ctx = (kma_ctx *)context->ulClen;
    aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;
    auth_data = (CK_BYTE *)aes_gcm_param->pAAD;
    auth_data_len = aes_gcm_param->ulAADLen;
    tag_data = out_data + in_data_len;
    tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;

    /* perform one-part encryption/decryption */
    rc = ica_aes_gcm_kma_update(in_data, out_data,
                                encrypt ? in_data_len : in_data_len - tag_data_len,
                                auth_data, auth_data_len,
                                1, 1, gcm_ctx);
    if (rc != 0) {
        TRACE_ERROR("ica_aes_gcm_kma_update failed, rc=%ld.\n", rc);
        *out_data_len = 0;
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (encrypt) {
        /* encrypt: provide authentication tag and append it to out_data */
        rc = ica_aes_gcm_kma_get_tag(tag_data, tag_data_len, gcm_ctx);
        if (rc == 0) {
            *out_data_len = in_data_len + tag_data_len;
        } else {
            TRACE_ERROR("ica_aes_gcm_kma_get_tag failed, rc=%ld.\n", rc);
            *out_data_len = 0;
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        /* decrypt: verify tag, which is appended to encrypted data */
        tag_data = in_data + in_data_len - tag_data_len;
        rc = ica_aes_gcm_kma_verify_tag(tag_data, tag_data_len, gcm_ctx);
        if (rc == 0) {
            *out_data_len = in_data_len - tag_data_len;
        } else {
            TRACE_ERROR("ica_aes_gcm_kma_verify_tag failed, rc=%ld.\n", rc);
            *out_data_len = 0;
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

done:

    ica_aes_gcm_kma_ctx_free(gcm_ctx);
    context->ulClen = (CK_ULONG)0;

    return rc;
}

CK_RV new_gcm_specific_aes_gcm_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                                      CK_ULONG in_data_len, CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    kma_ctx *gcm_ctx = NULL;
    CK_BYTE *auth_data, *buffer = NULL;
    CK_ULONG total, tag_data_len, remain, auth_data_len, out_len;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);

    context = (AES_GCM_CONTEXT *)ctx->context;
    gcm_ctx = (kma_ctx *)context->ulClen;
    aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;
    auth_data = (CK_BYTE *)aes_gcm_param->pAAD;
    auth_data_len = aes_gcm_param->ulAADLen;
    tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;
    total = context->len + in_data_len;

    /* if there isn't enough data to make a block, just save it */
    if (save_data_in_context(in_data, in_data_len, tag_data_len, context,
                             encrypt, total, &remain)) {
        *out_data_len = 0;
        return CKR_OK;
    }

    /* At least we have 1 block */
    out_len = total - remain;

    buffer = (CK_BYTE *)malloc(out_len);
    if (!buffer) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (encrypt) {
        /* copy all the leftover data from previous encryption first */
        memcpy(buffer, context->data, context->len);
        memcpy(buffer + context->len, in_data, out_len - context->len);

        TRACE_DEVEL("plaintext length (%ld bytes).\n", in_data_len);

        rc = ica_aes_gcm_kma_update(buffer, out_data, out_len,
                                    auth_data, auth_data_len,
                                    1, 0, gcm_ctx);

        /* save any remaining data */
        if (remain != 0)
            memcpy(context->data, in_data + (in_data_len - remain), remain);
        context->len = remain;
    } else {
        /* decrypt */
        /* copy all the leftover data from previous decryption first */
        if (in_data_len >= tag_data_len) {      /* case 1  */
            /* copy complete context to buffer first */
            memcpy(buffer, context->data, context->len);
            /* Append in_data to buffer */
            memcpy(buffer + context->len, in_data, out_len - context->len);
            /* copy remaining data to context */
            memcpy(context->data, in_data + out_len - context->len, remain);
            context->len = remain;
        } else {                /* case 2 - partial data */
            memcpy(buffer, context->data, AES_BLOCK_SIZE);
            memmove(context->data, context->data + AES_BLOCK_SIZE,
                    context->len - AES_BLOCK_SIZE);
            memcpy(context->data + context->len - AES_BLOCK_SIZE,
                   in_data, in_data_len);
            context->len = context->len - AES_BLOCK_SIZE + in_data_len;
        }

        rc = ica_aes_gcm_kma_update(buffer, out_data, out_len,
                                    auth_data, auth_data_len,
                                    1, 0, gcm_ctx);
    }

    if (rc != 0) {
        TRACE_ERROR("ica_aes_gcm_kma_update failed, rc=%ld.\n", rc);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *out_data_len = out_len;

done:
    if (buffer)
        free(buffer);

    return rc;
}

CK_RV new_gcm_specific_aes_gcm_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                     ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                                     CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    CK_RV rc = CKR_OK;
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    kma_ctx *gcm_ctx = NULL;
    CK_BYTE *final_tag_data;
    CK_ULONG tag_data_len;
    CK_BYTE tmp_tag[16];

    UNUSED(tokdata);
    UNUSED(sess);

    context = (AES_GCM_CONTEXT *)ctx->context;
    gcm_ctx = (kma_ctx *)context->ulClen;
    aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;
    tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;

    if (encrypt) {
        if (context->len != 0) {
            /* Perform final update with rest of data to calculate final tag */
            rc = ica_aes_gcm_kma_update(context->data, out_data, context->len,
                                        NULL, 0, 1,1, gcm_ctx);
            if (rc != 0) {
                TRACE_ERROR("ica_aes_gcm_kma_update failed, rc=%ld\n",rc);
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            *out_data_len = context->len + tag_data_len;
        } else {
            /* Perform final update without data to calculate final tag */
            rc = ica_aes_gcm_kma_update(NULL, NULL, 0, NULL, 0, 1, 1, gcm_ctx);
            if (rc != 0) {
                TRACE_ERROR("ica_aes_gcm_kma_update failed, rc=%ld\n",rc);
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            *out_data_len = tag_data_len;
        }

        TRACE_DEVEL("GCM Final: context->len=%ld, tag_data_len=%ld, "
                    "out_data_len=%ld\n",
                    context->len, tag_data_len, *out_data_len);

        rc = ica_aes_gcm_kma_get_tag(tmp_tag, tag_data_len, gcm_ctx);
        if (rc != 0) {
            TRACE_ERROR("ica_aes_gcm_kma_get_tag failed, rc=%ld.\n", rc);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        memcpy(out_data + context->len, tmp_tag, tag_data_len);
    } else {
        /* decrypt */
        if (context->len > tag_data_len) {
            /* Perform final update with rest of data to calculate final tag */
            rc = ica_aes_gcm_kma_update(context->data, out_data,
                                        context->len - tag_data_len,
                                        NULL, 0, 1, 1, gcm_ctx);
            if (rc != 0) {
                TRACE_ERROR("ica_aes_gcm_kma_update failed, rc=%ld.\n",rc);
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            *out_data_len = context->len - tag_data_len;

        } else if (context->len == tag_data_len) {
            /* remaining data are tag data */
            *out_data_len = 0;

            /* Perform final update without data to calculate final tag */
            rc = ica_aes_gcm_kma_update(NULL, NULL, 0, NULL, 0, 1, 1, gcm_ctx);
            if (rc != 0) {
                TRACE_ERROR("ica_aes_gcm_kma_update failed, rc=%ld.\n",rc);
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
        } else {                /* (context->len < tag_data_len) */
            TRACE_ERROR("Incoming data are not consistent.\n");
            rc = CKR_DATA_INVALID;
            goto done;
        }

        final_tag_data = context->data + context->len - tag_data_len;

        rc = ica_aes_gcm_kma_verify_tag(final_tag_data, tag_data_len, gcm_ctx);
        if (rc != 0) {
            TRACE_ERROR("ica_aes_gcm_kma_verify_tag failed, rc=%ld.\n", rc);
            rc = CKR_FUNCTION_FAILED;
        }
    }

done:
    ica_aes_gcm_kma_ctx_free(gcm_ctx);
    context->ulClen = (CK_ULONG)0;

    return rc;
}
#endif

CK_RV token_specific_rsa_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_encrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_decrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             os_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_sign(tokdata, sess, in_data, in_data_len,
                                          out_data, out_data_len, key_obj,
                                          os_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BYTE *in_data, CK_ULONG in_data_len,
                                CK_BYTE *signature, CK_ULONG sig_len,
                                OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_verify(tokdata, sess, in_data, in_data_len,
                                          signature, sig_len, key_obj,
                                          os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_verify_recover(STDLL_TokData_t *tokdata,
                                        CK_BYTE *signature, CK_ULONG sig_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len,
                                        OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_verify_recover(tokdata, signature,
                                                    sig_len, out_data,
                                                    out_data_len, key_obj,
                                                    os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *sig, CK_ULONG *sig_len)
{
    return openssl_specific_rsa_pss_sign(tokdata, sess, ctx, in_data,
                                         in_data_len, sig, sig_len,
                                         os_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                    SIGN_VERIFY_CONTEXT *ctx,
                                    CK_BYTE *in_data, CK_ULONG in_data_len,
                                    CK_BYTE *signature, CK_ULONG sig_len)
{
    return openssl_specific_rsa_pss_verify(tokdata, sess, ctx, in_data,
                                           in_data_len, signature, sig_len,
                                           os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_x509_encrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_encrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_x509_decrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_decrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             os_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_x509_sign(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BYTE *out_data,
                                   CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_sign(tokdata, in_data, in_data_len,
                                          out_data, out_data_len, key_obj,
                                          os_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_x509_verify(STDLL_TokData_t *tokdata,
                                     CK_BYTE *in_data, CK_ULONG in_data_len,
                                     CK_BYTE *signature, CK_ULONG sig_len,
                                     OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_verify(tokdata, in_data, in_data_len,
                                            signature, sig_len, key_obj,
                                            os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                                             CK_BYTE *signature,
                                             CK_ULONG sig_len,
                                             CK_BYTE *out_data,
                                             CK_ULONG *out_data_len,
                                             OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_verify_recover(tokdata, signature, sig_len,
                                                    out_data, out_data_len,
                                                    key_obj,
                                                    os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_oaep_encrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    return openssl_specific_rsa_oaep_encrypt(tokdata, ctx, in_data,
                                             in_data_len, out_data,
                                             out_data_len, hash, hlen,
                                             os_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_oaep_decrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    return openssl_specific_rsa_oaep_decrypt(tokdata, ctx, in_data,
                                             in_data_len, out_data,
                                             out_data_len, hash, hlen,
                                             os_specific_rsa_decrypt);
}

CK_RV token_specific_aes_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **key, CK_ULONG *len, CK_ULONG keysize,
                                 CK_BBOOL *is_opaque)
{
    UNUSED(tmpl);

    *key = malloc(keysize);
    if (*key == NULL)
        return CKR_HOST_MEMORY;
    *len = keysize;
    *is_opaque = FALSE;

    return rng_generate(tokdata, *key, keysize);
}

CK_RV token_specific_aes_xts_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                     CK_BYTE **key, CK_ULONG *len,
                                     CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    CK_RV rc;

    UNUSED(tmpl);

    *key = malloc(keysize);
    if (*key == NULL)
        return CKR_HOST_MEMORY;
    *len = keysize;
    *is_opaque = FALSE;

    do {
        rc = rng_generate(tokdata, *key, keysize);
        if (rc != CKR_OK)
            return rc;
    } while (memcmp(*key, (*key) + keysize / 2, keysize / 2) == 0);

    return CKR_OK;
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t *tokdata,
                             SESSION *sess, CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    int rc = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(sess);

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_ecb(tokdata, in_data, in_data_len,
                                        out_data, out_data_len, key, encrypt);

    /*
     * checks for input and output data length and block sizes
     * are already being carried out in mech_aes.c
     * so we skip those
     */
    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (encrypt) {
        rc = ica_aes_ecb(in_data, out_data, in_data_len, attr->pValue,
                         attr->ulValueLen, ICA_ENCRYPT);
    } else {
        rc = ica_aes_ecb(in_data, out_data, in_data_len, attr->pValue,
                         attr->ulValueLen, ICA_DECRYPT);
    }
    if (rc != 0) {
        (*out_data_len) = 0;
        rc = CKR_FUNCTION_FAILED;
    } else {
        (*out_data_len) = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_aes_cbc(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(sess);

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_cbc(tokdata, in_data, in_data_len,
                                        out_data, out_data_len, key,
                                        init_v, encrypt);

    /*
     * checks for input and output data length and block sizes
     * are already being carried out in mech_aes.c
     * so we skip those
     */

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (encrypt) {
        rc = ica_aes_cbc(in_data, out_data, in_data_len, attr->pValue,
                         attr->ulValueLen, init_v, ICA_ENCRYPT);
    } else {
        rc = ica_aes_cbc(in_data, out_data, in_data_len, attr->pValue,
                         attr->ulValueLen, init_v, ICA_DECRYPT);
    }
    if (rc != 0) {
        (*out_data_len) = 0;
        rc = CKR_FUNCTION_FAILED;
    } else {
        (*out_data_len) = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_aes_ctr(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key,
                             CK_BYTE *counterblock,
                             CK_ULONG counter_width, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_ctr(tokdata, in_data, in_data_len,
                                        out_data, out_data_len, key,
                                        counterblock, counter_width, encrypt);

    /*
     * checks for input and output data length and block sizes
     * are already being carried out in mech_aes.c
     * so we skip those
     */
    /* in libica for AES-Counter Mode if uses one function for both encrypt and
     * decrypt, so they use variable direction to know if the data is to be
     * encrypted or decrypted
     * 0 -- Decrypt
     * 1 -- Encrypt
     */

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (encrypt) {
        rc = ica_aes_ctr(in_data, out_data, (unsigned int) in_data_len,
                         attr->pValue, (unsigned int) attr->ulValueLen,
                         counterblock, (unsigned int) counter_width, 1);
    } else {
        rc = ica_aes_ctr(in_data, out_data, (unsigned int) in_data_len,
                         attr->pValue, (unsigned int) attr->ulValueLen,
                         counterblock, (unsigned int) counter_width, 0);
    }
    if (rc != 0) {
        (*out_data_len) = 0;
        rc = CKR_FUNCTION_FAILED;
    } else {
        (*out_data_len) = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                  ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
                                  CK_OBJECT_HANDLE key, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_OK;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    AES_GCM_CONTEXT *context = NULL;
    CK_BYTE *icv, *icb, *ucb, *subkey;
    CK_ULONG icv_length;

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_gcm_init(tokdata, sess, ctx, mech,
                                             key, encrypt);

    /* find key object */
    rc = object_mgr_find_in_map1(tokdata, key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    /* get the key value */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        goto done;
    }

#ifdef AES_GCM_KMA
    if (ica_data->ica_new_gcm_available) {
        rc = new_gcm_specific_aes_gcm_init(tokdata, sess, ctx, mech,
                                           attr->pValue, attr->ulValueLen,
                                           encrypt);
        goto done;
    }
#endif

    /* prepare initial counterblock */
    aes_gcm_param = (CK_GCM_PARAMS *) mech->pParameter;
    context = (AES_GCM_CONTEXT *) ctx->context;

    context->ulAlen = aes_gcm_param->ulAADLen;
    icb = (CK_BYTE *) context->icb;
    ucb = (CK_BYTE *) context->ucb;
    subkey = (CK_BYTE *) context->subkey;

    icv = (CK_BYTE *) aes_gcm_param->pIv;
    icv_length = aes_gcm_param->ulIvLen;

    if (encrypt) {
        rc = ica_aes_gcm_initialize(icv, icv_length,
                                    attr->pValue, attr->ulValueLen,
                                    icb, ucb, subkey, 1);
    } else {
        rc = ica_aes_gcm_initialize(icv, icv_length,
                                    attr->pValue, attr->ulValueLen,
                                    icb, ucb, subkey, 0);
    }
    if (rc != 0) {
        TRACE_ERROR("ica_aes_gcm_initialize() failed.\n");
        goto done;
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV token_specific_aes_gcm(STDLL_TokData_t *tokdata, SESSION *sess,
                             ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    OBJECT *key = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    CK_BYTE *counterblock;
    CK_ULONG counter_width;
    CK_BYTE *tag_data, *auth_data;
    CK_ULONG auth_data_len;
    CK_ULONG tag_data_len;

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_gcm(tokdata, sess, ctx, in_data,
                                        in_data_len, out_data, out_data_len,
                                        encrypt);

#ifdef AES_GCM_KMA
    if (ica_data->ica_new_gcm_available)
        return new_gcm_specific_aes_gcm(tokdata, sess, ctx, in_data,
                                        in_data_len, out_data, out_data_len,
                                        encrypt);

#endif

    /*
     * Checks for input and output data length and block sizes are already
     * being carried out in mech_aes.c, so we skip those
     *
     * libica for AES-GCM Mode uses one function for both encrypt
     * and decrypt, so they use the variable 'direction' to know if
     * the data is to be encrypted or decrypted.
     * 0 -- Decrypt
     * 1 -- Encrypt
     */

    aes_gcm_param = (CK_GCM_PARAMS *) ctx->mech.pParameter;
    counterblock = (CK_BYTE *) aes_gcm_param->pIv;
    counter_width = aes_gcm_param->ulIvLen;
    auth_data = (CK_BYTE *) aes_gcm_param->pAAD;
    auth_data_len = aes_gcm_param->ulAADLen;
    tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;

    /* find key object */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    /* get key value */
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        goto done;
    }

    if (encrypt) {
        tag_data = out_data + in_data_len;
        rc = ica_aes_gcm(in_data, (unsigned int) in_data_len, out_data,
                         counterblock, (unsigned int) counter_width,
                         auth_data, (unsigned int) auth_data_len,
                         tag_data, AES_BLOCK_SIZE, attr->pValue,
                         (unsigned int) attr->ulValueLen, 1);
        if (rc == 0) {
            (*out_data_len) = in_data_len + tag_data_len;
            rc = CKR_OK;
        }
    } else {
        unsigned int len;

        tag_data = in_data + in_data_len - tag_data_len;
        len = in_data_len - tag_data_len;
        rc = ica_aes_gcm(out_data,
                         (unsigned int) len, in_data, counterblock,
                         (unsigned int) counter_width, auth_data,
                         (unsigned int) auth_data_len, tag_data,
                         (unsigned int) tag_data_len, attr->pValue,
                         (unsigned int) attr->ulValueLen, 0);
        if (rc == 0) {
            (*out_data_len) = len;
            rc = CKR_OK;
        }
    }

    if (rc != 0) {
        TRACE_ERROR("ica_aes_gcm failed with rc = %ld.\n", rc);
        (*out_data_len) = 0;
        rc = CKR_FUNCTION_FAILED;
    }

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}

CK_RV token_specific_aes_gcm_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                    ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                                    CK_ULONG in_data_len, CK_BYTE *out_data,
                                    CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *key = NULL;
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    CK_ULONG total, tag_data_len, remain, auth_data_len;
    CK_ULONG out_len;
    CK_BYTE *auth_data, *tag_data;
    CK_BYTE *ucb, *subkey;
    CK_BYTE *buffer = NULL;

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_gcm_update(tokdata, sess, ctx, in_data,
                                               in_data_len, out_data,
                                               out_data_len, encrypt);

#ifdef AES_GCM_KMA
    if (ica_data->ica_new_gcm_available)
        return new_gcm_specific_aes_gcm_update(tokdata, sess, ctx, in_data,
                                        in_data_len, out_data, out_data_len,
                                        encrypt);
#endif

    context = (AES_GCM_CONTEXT *) ctx->context;
    total = (context->len + in_data_len);
    ucb = (CK_BYTE *) context->ucb;
    tag_data = context->hash;
    auth_data_len = context->ulAlen;
    subkey = (CK_BYTE *) context->subkey;

    aes_gcm_param = (CK_GCM_PARAMS *) ctx->mech.pParameter;
    tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;
    auth_data = (CK_BYTE *) aes_gcm_param->pAAD;

    /* if there isn't enough data to make a block, just save it */
    if (save_data_in_context(in_data, in_data_len, tag_data_len, context,
                             encrypt, total, &remain)) {
        *out_data_len = 0;
        return CKR_OK;
    }

    /* At least we have 1 block */
    /* find key object */
    rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    /* get key value */
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        goto done;
    }

    out_len = total - remain;

    buffer = (CK_BYTE *) malloc(out_len);
    if (!buffer) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (encrypt) {
        /* copy all the leftover data from previous encryption first */
        memcpy(buffer, context->data, context->len);
        memcpy(buffer + context->len, in_data, out_len - context->len);

        TRACE_DEVEL("plaintext length (%ld bytes).\n", in_data_len);

        rc = ica_aes_gcm_intermediate(buffer, (unsigned int) out_len,
                                      out_data, ucb, auth_data,
                                      (unsigned int) auth_data_len,
                                      tag_data, AES_BLOCK_SIZE,
                                      attr->pValue,
                                      (unsigned int) attr->ulValueLen,
                                      subkey, 1);

        /* save any remaining data */
        if (remain != 0)
            memcpy(context->data, in_data + (in_data_len - remain), remain);
        context->len = remain;

    } else {
        /* decrypt */
        /* copy all the leftover data from previous encryption first */
        if (in_data_len >= tag_data_len) {      /* case 1  */
            /* copy complete context to buffer first */
            memcpy(buffer, context->data, context->len);
            /* Append in_data to buffer */
            memcpy(buffer + context->len, in_data, out_len - context->len);
            /* copy remaining data to context */
            memcpy(context->data, in_data + out_len - context->len, remain);
            context->len = remain;
        } else {                /* case 2 - partial data */
            memcpy(buffer, context->data, AES_BLOCK_SIZE);
            memmove(context->data, context->data + AES_BLOCK_SIZE,
                    context->len - AES_BLOCK_SIZE);
            memcpy(context->data + context->len - AES_BLOCK_SIZE,
                   in_data, in_data_len);
            context->len = context->len - AES_BLOCK_SIZE + in_data_len;
        }

        rc = ica_aes_gcm_intermediate(out_data, (unsigned int) out_len,
                                      buffer, ucb, auth_data,
                                      (unsigned int) auth_data_len,
                                      tag_data,
                                      (unsigned int) tag_data_len,
                                      attr->pValue,
                                      (unsigned int) attr->ulValueLen,
                                      subkey, 0);

    }

    if (rc != 0) {
        TRACE_ERROR("ica_aes_gcm_update failed with rc = %ld.\n", rc);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    (*out_data_len) = out_len;

    context->ulClen += out_len;

    /* AAD only processed in first update sequence,
     * mark it empty for all subsequent calls
     */
    context->ulAlen = 0;

done:
    if (buffer)
        free(buffer);

    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}

CK_RV token_specific_aes_gcm_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                   ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                                   CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *key = NULL;
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    CK_BYTE *icb, *ucb;
    CK_BYTE *tag_data, *subkey, *auth_data, *final_tag_data;
    CK_ULONG auth_data_len, tag_data_len;
    CK_BYTE *buffer = NULL;

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_gcm_final(tokdata, sess, ctx, out_data,
                                              out_data_len, encrypt);

#ifdef AES_GCM_KMA
    if (ica_data->ica_new_gcm_available)
        return new_gcm_specific_aes_gcm_final(tokdata, sess, ctx, out_data,
                                              out_data_len, encrypt);
#endif

    /* find key object */
    rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        goto done;
    }

    context = (AES_GCM_CONTEXT *) ctx->context;
    ucb = (CK_BYTE *) context->ucb;
    icb = (CK_BYTE *) context->icb;
    tag_data = context->hash;
    subkey = (CK_BYTE *) context->subkey;

    aes_gcm_param = (CK_GCM_PARAMS *) ctx->mech.pParameter;
    auth_data = (CK_BYTE *) aes_gcm_param->pAAD;
    auth_data_len = aes_gcm_param->ulAADLen;
    tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;

    if (encrypt) {
        if (context->len != 0) {
            buffer = (CK_BYTE *) malloc(AES_BLOCK_SIZE);
            if (!buffer) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memcpy(buffer, context->data, context->len);

            rc = ica_aes_gcm_intermediate(buffer, context->len,
                                          out_data, ucb, auth_data,
                                          context->ulAlen, tag_data,
                                          AES_BLOCK_SIZE, attr->pValue,
                                          (unsigned int) attr->ulValueLen,
                                          subkey, 1);

            if (rc != 0) {
                TRACE_ERROR("ica_aes_gcm_intermediate() "
                            "failed to encrypt\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }

            context->ulClen += context->len;
            *out_data_len = context->len + tag_data_len;
        } else {
            *out_data_len = tag_data_len;
        }

        TRACE_DEVEL("GCM Final: context->len=%ld, tag_data_len=%ld, "
                    "out_data_len=%ld\n",
                    context->len, tag_data_len, *out_data_len);

        rc = ica_aes_gcm_last(icb, (unsigned int) auth_data_len,
                              (unsigned int) context->ulClen, tag_data,
                              NULL, 0, attr->pValue,
                              (unsigned int) attr->ulValueLen, subkey, 1);

        if (rc != 0) {
            TRACE_ERROR("ica_aes_gcm_final failed with rc = %ld.\n", rc);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        memcpy(out_data + context->len, tag_data, tag_data_len);
    } else {
        /* decrypt */

        if (context->len > tag_data_len) {
            buffer = (CK_BYTE *) malloc(AES_BLOCK_SIZE);
            if (!buffer) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memcpy(buffer, context->data, context->len - tag_data_len);

            rc = ica_aes_gcm_intermediate(out_data,
                                          (unsigned int) context->len -
                                          tag_data_len, buffer, ucb, auth_data,
                                          (unsigned int) context->ulAlen,
                                          tag_data, AES_BLOCK_SIZE,
                                          attr->pValue,
                                          (unsigned int) attr->ulValueLen,
                                          subkey, 0);

            if (rc != 0) {
                TRACE_ERROR("ica_aes_gcm_intermediate() "
                            "failed to decrypt.\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            (*out_data_len) = context->len - tag_data_len;
            context->ulClen += context->len - tag_data_len;

        } else if (context->len == tag_data_len) {
            /* remaining data are tag data */
            *out_data_len = 0;
        } else {                /* (context->len < tag_data_len) */
            TRACE_ERROR("Incoming data are not consistent.\n");
            rc = CKR_DATA_INVALID;
            goto done;
        }

        final_tag_data = context->data + context->len - tag_data_len;

        rc = ica_aes_gcm_last(icb, aes_gcm_param->ulAADLen,
                              context->ulClen, tag_data, final_tag_data,
                              tag_data_len, attr->pValue,
                              (unsigned int) attr->ulValueLen, subkey, 0);
        if (rc != 0) {
            TRACE_ERROR("ica_aes_gcm_final failed with rc = %ld.\n", rc);
            rc = CKR_FUNCTION_FAILED;
        }
    }

done:
    if (buffer)
        free(buffer);

    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}

/**
 * In libica for AES-OFB Mode it uses one function for both encrypt and decrypt
 * The variable direction is used as an indicator either for encrypt or decrypt
 * 0 -- Decrypt
 * 1 -- Encrypt
 */
CK_RV token_specific_aes_ofb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             OBJECT *key, CK_BYTE *init_v, uint_32 direction)
{
#if OPENSSL_VERSION_PREREQ(3, 0) || OPENSSL_VERSION_NUMBER >= 0x101010cfL
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
#endif
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

#if OPENSSL_VERSION_PREREQ(3, 0) || OPENSSL_VERSION_NUMBER >= 0x101010cfL
    /*
     * AES-OFB/CFB currently only works with >= OpenSSl 3.0 or >= OpenSSL 1.1.1l,
     * due to a bug in OpenSSL <= 1.1.1k in s390x_aes_ofb_cipher() not updating
     * the IV in the context.
     */
    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_ofb(tokdata, in_data, in_data_len,
                                        out_data, key, init_v, direction);
#else
    UNUSED(tokdata);
#endif

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    rc = ica_aes_ofb(in_data, out_data, (unsigned long) in_data_len,
                     attr->pValue, (unsigned int) attr->ulValueLen,
                     init_v, direction);

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

/**
 * In libica for AES-CFB Mode it uses one function for both encrypt and decrypt
 * The variable direction is used as an indicator either for encrypt or decrypt
 *  0 -- Decrypt
 *  1 -- Encrypt
 */
CK_RV token_specific_aes_cfb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             OBJECT *key, CK_BYTE *init_v, uint_32 lcfb,
                             uint_32 direction)
{
#if OPENSSL_VERSION_PREREQ(3, 0) || OPENSSL_VERSION_NUMBER >= 0x101010cfL
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
#endif
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

#if OPENSSL_VERSION_PREREQ(3, 0) || OPENSSL_VERSION_NUMBER >= 0x101010cfL
    /*
     * AES-OFB/CFB currently only works with >= OpenSSl 3.0 or >= OpenSSL 1.1.1l,
     * due to a bug in OpenSSL <= 1.1.1k in s390x_aes_ofb_cipher() not updating
     * the IV in the context.
     */
    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_cfb(tokdata, in_data, in_data_len,
                                        out_data, key, init_v, lcfb,
                                        direction);
#else
    UNUSED(tokdata);
#endif

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    rc = ica_aes_cfb(in_data, out_data, (unsigned long) in_data_len,
                     attr->pValue, (unsigned int) attr->ulValueLen, init_v,
                     lcfb, direction);

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_specific_aes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                             CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_mac(tokdata, message, message_len,
                                        key, mac);

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    rc = ica_aes_cmac_intermediate(message, (unsigned long) message_len,
                                   attr->pValue,
                                   (unsigned int) attr->ulValueLen, mac);

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_specific_aes_cmac(STDLL_TokData_t *tokdata, SESSION *session, CK_BYTE *message,
                              CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                              CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(session);

    if (!ica_data->ica_aes_available)
        return openssl_specific_aes_cmac(tokdata, message, message_len,
                                        key, mac, first, last, ctx);

    if (key == NULL)
        return CKR_ARGUMENTS_BAD;

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (first && last) {
        rc = ica_aes_cmac(message, (unsigned long) message_len,
                          mac, AES_BLOCK_SIZE,
                          attr->pValue, (unsigned int) attr->ulValueLen,
                          ICA_ENCRYPT);
    } else if (!last) {
        rc = ica_aes_cmac_intermediate(message, (unsigned long) message_len,
                                       attr->pValue,
                                       (unsigned int) attr->ulValueLen,
                                       mac);
    } else {
        rc = ica_aes_cmac_last(message, (unsigned long) message_len,
                               mac, AES_BLOCK_SIZE,
                               attr->pValue, (unsigned int) attr->ulValueLen,
                               mac, ICA_ENCRYPT);
    }

    if (rc != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_specific_aes_xts(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj, CK_BYTE *tweak,
                             CK_BOOL encrypt, CK_BBOOL initial, CK_BBOOL final,
                             CK_BYTE* iv)
{
    UNUSED(sess);

    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_ATTRIBUTE *key_attr;
    CK_RV rc;

    UNUSED(tokdata);

    if (!ica_data->ica_aes_available || p_ica_aes_xts_ex == NULL)
        return openssl_specific_aes_xts(tokdata, in_data, in_data_len,
                                        out_data, out_data_len, key_obj,
                                        tweak, encrypt, initial, final, iv);

    /* Full block size unless final call */
    if (!final && (in_data_len % AES_BLOCK_SIZE) != 0)
        return CKR_DATA_LEN_RANGE;
    /* Final block must be at least one full block */
    if (final && in_data_len < AES_BLOCK_SIZE)
        return CKR_DATA_LEN_RANGE;

    if (out_data == NULL) {
        *out_data_len = in_data_len;
        return CKR_OK;
    }

    if (*out_data_len < in_data_len)
        return CKR_BUFFER_TOO_SMALL;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE,
                                          &key_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    rc = p_ica_aes_xts_ex(in_data, out_data, in_data_len,
                          key_attr->pValue, (unsigned char *)key_attr->pValue +
                                                   key_attr->ulValueLen / 2,
                          key_attr->ulValueLen / 2,
                          initial ? tweak : NULL, iv,
                          encrypt ? ICA_ENCRYPT : ICA_DECRYPT);

    if (rc == 0) {
        *out_data_len = in_data_len;
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
    }

    return rc;
}

typedef struct _REF_MECH_LIST_ELEMENT {
    CK_ULONG lica_idx; /* 0 means its a combined mechanism */
    CK_MECHANISM_TYPE mech_type;
    CK_MECHANISM_INFO mech_info;
} REF_MECH_LIST_ELEMENT;

static const REF_MECH_LIST_ELEMENT ref_mech_list[] = {
    {RSA_KEY_GEN_ME, CKM_RSA_PKCS_KEY_PAIR_GEN,
     {512, 4096, CKF_GENERATE_KEY_PAIR}
    },
    {P_RNG, CKM_DES_KEY_GEN, {8, 8, CKF_GENERATE}},
    {P_RNG, CKM_DES3_KEY_GEN, {24, 24, CKF_GENERATE}},
    {RSA_ME, CKM_RSA_PKCS,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP |
      CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER}
    },
    {0, CKM_SHA1_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA224_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA256_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA384_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA512_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_224_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_256_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_384_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_512_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
#if !(NOX509)
    {RSA_ME, CKM_RSA_X_509,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP |
      CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER}
    },
#endif
    {0, CKM_RSA_PKCS_OAEP,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {0, CKM_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA1_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA224_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA256_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA384_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA512_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_224_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_256_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_384_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_SHA3_512_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {0, CKM_RSA_AES_KEY_WRAP, {512, 4096, CKF_WRAP | CKF_UNWRAP}},
    {DES_ECB, CKM_DES_ECB,
     {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {DES_CBC, CKM_DES_CBC,
     {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {DES_CBC, CKM_DES_CBC_PAD,
     {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {DES3_ECB, CKM_DES3_ECB,
     {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {DES3_ECB, CKM_DES3_CBC,
     {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {DES3_CBC, CKM_DES3_CBC_PAD,
     {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {DES3_CMAC, CKM_DES3_MAC, {24, 24, CKF_SIGN | CKF_VERIFY}},
    {DES3_CMAC, CKM_DES3_MAC_GENERAL, {24, 24, CKF_SIGN | CKF_VERIFY}},
    {DES3_CMAC, CKM_DES3_CMAC, {16, 24, CKF_SIGN | CKF_VERIFY}},
    {DES3_CMAC, CKM_DES3_CMAC_GENERAL, {16, 24, CKF_SIGN | CKF_VERIFY}},
    {DES_CFB, CKM_DES_CFB8, {8, 8, CKF_ENCRYPT | CKF_DECRYPT}},
    {DES_OFB, CKM_DES_OFB64, {8, 8, CKF_ENCRYPT | CKF_DECRYPT}},
    {DES_CFB, CKM_DES_CFB64, {8, 8, CKF_ENCRYPT | CKF_DECRYPT}},
    {SHA1, CKM_SHA_1, {0, 0, CKF_DIGEST}},
    {SHA1, CKM_SHA_1_HMAC, {80, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA1, CKM_SHA_1_HMAC_GENERAL, {80, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA1, CKM_SHA1_KEY_DERIVATION, {8, 160, CKF_DERIVE}},
    {SHA224, CKM_SHA224, {0, 0, CKF_DIGEST}},
    {SHA224, CKM_SHA224_HMAC, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA224, CKM_SHA224_HMAC_GENERAL, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA224, CKM_SHA224_KEY_DERIVATION, {8, 224, CKF_DERIVE}},
    {SHA256, CKM_SHA256, {0, 0, CKF_DIGEST}},
    {SHA256, CKM_SHA256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA256, CKM_SHA256_HMAC_GENERAL, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA256, CKM_SHA256_KEY_DERIVATION, {8, 256, CKF_DERIVE}},
    {SHA384, CKM_SHA384, {0, 0, CKF_DIGEST}},
    {SHA384, CKM_SHA384_HMAC, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA384, CKM_SHA384_HMAC_GENERAL, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA384, CKM_SHA384_KEY_DERIVATION, {8, 384, CKF_DERIVE}},
    {SHA512, CKM_SHA512, {0, 0, CKF_DIGEST}},
    {SHA512, CKM_SHA512_HMAC, {256, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA512, CKM_SHA512_HMAC_GENERAL, {256, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA512, CKM_SHA512_KEY_DERIVATION, {8, 512, CKF_DERIVE}},
#ifdef SHA512_224
    {SHA512_224, CKM_SHA512_224, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA512_224, CKM_SHA512_224_HMAC, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA512_224, CKM_SHA512_224_HMAC_GENERAL, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA512_224, CKM_SHA512_224_KEY_DERIVATION, {8, 224, CKF_DERIVE}},
#endif
#ifdef SHA512_256
    {SHA512_256, CKM_SHA512_256, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA512_256, CKM_SHA512_256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA512_256, CKM_SHA512_256_HMAC_GENERAL, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA512_256, CKM_SHA512_256_KEY_DERIVATION, {8, 256, CKF_DERIVE}},
#endif
#ifdef SHA3_224
    {SHA3_224, CKM_SHA3_224, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_224, CKM_SHA3_224_HMAC, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_224, CKM_SHA3_224_HMAC_GENERAL, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_224, CKM_SHA3_224_KEY_DERIVATION, {8, 224, CKF_DERIVE}},
    {SHA3_224, CKM_IBM_SHA3_224, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_224, CKM_IBM_SHA3_224_HMAC, {112, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef SHA3_256
    {SHA3_256, CKM_SHA3_256, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_256, CKM_SHA3_256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_256, CKM_SHA3_256_HMAC_GENERAL, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_256, CKM_SHA3_256_KEY_DERIVATION, {8, 256, CKF_DERIVE}},
    {SHA3_256, CKM_IBM_SHA3_256, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_256, CKM_IBM_SHA3_256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef SHA3_384
    {SHA3_384, CKM_SHA3_384, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_384, CKM_SHA3_384_HMAC, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_384, CKM_SHA3_384_HMAC_GENERAL, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_384, CKM_SHA3_384_KEY_DERIVATION, {8, 384, CKF_DERIVE}},
    {SHA3_384, CKM_IBM_SHA3_384, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_384, CKM_IBM_SHA3_384_HMAC, {192, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef SHA3_512
    {SHA3_512, CKM_SHA3_512, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_512, CKM_SHA3_512_HMAC, {256, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_512, CKM_SHA3_512_HMAC_GENERAL, {256, 2048, CKF_SIGN | CKF_VERIFY}},
    {SHA3_512, CKM_SHA3_512_KEY_DERIVATION, {8, 512, CKF_DERIVE}},
    {SHA3_512, CKM_IBM_SHA3_512, {0, 0, CKF_HW | CKF_DIGEST}},
    {SHA3_512, CKM_IBM_SHA3_512_HMAC, {256, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NOMD5)
    {53, CKM_MD5, {0, 0, CKF_DIGEST}},
    {54, CKM_MD5_HMAC, {8, 2048, CKF_SIGN | CKF_VERIFY}},
    {55, CKM_MD5_HMAC_GENERAL, {8, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef SHAKE128
    {SHAKE128, CKM_SHAKE_128_KEY_DERIVATION, {8, 2048, CKF_DERIVE}},
#endif
#ifdef SHAKE256
    {SHAKE256, CKM_SHAKE_256_KEY_DERIVATION, {8, 2048, CKF_DERIVE}},
#endif
    {P_RNG, CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
    {P_RNG, CKM_AES_XTS_KEY_GEN, {32, 64, CKF_GENERATE}},
    {AES_ECB, CKM_AES_ECB,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_CBC, CKM_AES_CBC,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_CBC, CKM_AES_CBC_PAD,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_OFB, CKM_AES_OFB,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_CFB, CKM_AES_CFB8,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_CFB, CKM_AES_CFB64,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_CFB, CKM_AES_CFB128,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_CTR, CKM_AES_CTR,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_GCM, CKM_AES_GCM,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {AES_CMAC, CKM_AES_MAC, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {AES_CMAC, CKM_AES_MAC_GENERAL, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {AES_CMAC, CKM_AES_CMAC, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {AES_CMAC, CKM_AES_CMAC_GENERAL, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {AES_XTS, CKM_AES_XTS,
     {32, 64, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
    },
    {AES_ECB, CKM_AES_KEY_WRAP,
     {32, 64, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {AES_ECB, CKM_AES_KEY_WRAP_PAD,
     {32, 64, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {AES_ECB, CKM_AES_KEY_WRAP_KWP,
     {32, 64, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {AES_ECB, CKM_AES_KEY_WRAP_PKCS7,
     {32, 64, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {P_RNG, CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA_1_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA224_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA256_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA384_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA512_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA512_224_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA512_256_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA3_224_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA3_256_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA3_384_KEY_GEN, {80, 2048, CKF_GENERATE}},
    {P_RNG, CKM_SHA3_512_KEY_GEN, {80, 2048, CKF_GENERATE}},
#ifndef NO_EC
    {EC_DH, CKM_ECDH1_DERIVE,
     {160, 521, CKF_DERIVE | CKF_EC_OID | CKF_EC_F_P | CKF_EC_UNCOMPRESS |
                CKF_EC_COMPRESS}
    },
    {EC_DSA_SIGN, CKM_ECDSA,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA1,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA224,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA256,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA384,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA512,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA3_224,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA3_256,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA3_384,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {0, CKM_ECDSA_SHA3_512,
     {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {EC_KGEN, CKM_EC_KEY_PAIR_GEN,
     {160, 521, CKF_GENERATE_KEY_PAIR | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}
    },
    {EC_DH, CKM_ECDH_AES_KEY_WRAP, {160, 521, CKF_WRAP | CKF_UNWRAP |
                                    CKF_EC_OID | CKF_EC_F_P |
                                    CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
#if OPENSSL_VERSION_PREREQ(3, 0)
#if defined ED25519_KEYGEN && ED448_KEYGEN
    {ED25519_KEYGEN, CKM_EC_EDWARDS_KEY_PAIR_GEN,
     {255, 448, CKF_GENERATE_KEY_PAIR | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_COMPRESS}
    },
#endif
#if defined X25519_KEYGEN && X448_KEYGEN
    {X25519_KEYGEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
     {255, 448, CKF_GENERATE_KEY_PAIR | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_COMPRESS}
    },
#endif
#if defined ED25519_SIGN && ED448_SIGN
    {ED25519_SIGN, CKM_EDDSA,
     {255, 448, CKF_SIGN | CKF_VERIFY | CKF_EC_OID | CKF_EC_F_P |
                CKF_EC_COMPRESS}
    },
#endif
#endif
#endif
};

static const CK_ULONG ref_mech_list_len =
    (sizeof(ref_mech_list) / sizeof(REF_MECH_LIST_ELEMENT));

CK_RV token_specific_get_mechanism_list(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount)
{
    return ock_generic_get_mechanism_list(tokdata, pMechanismList, pulCount, NULL);
}


CK_RV token_specific_get_mechanism_info(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_TYPE type,
                                        CK_MECHANISM_INFO_PTR pInfo)
{
    return ock_generic_get_mechanism_info(tokdata, type, pInfo, NULL);
}

static CK_RV getRefListIdxfromId(CK_ULONG ica_idx, CK_ULONG_PTR pRefIdx)
{
    unsigned int n;

    for (n = *pRefIdx; n < ref_mech_list_len; n++) {
        if (ica_idx == ref_mech_list[n].lica_idx) {
            *pRefIdx = n;
            return CKR_OK;
        }
    }

    return CKR_MECHANISM_INVALID;
}

static CK_RV getRefListIdxfromMech(CK_ULONG mech, CK_ULONG_PTR pRefIdx)
{
    unsigned int n;

    for (n = *pRefIdx; n < ref_mech_list_len; n++) {
        if (mech == ref_mech_list[n].mech_type) {
            *pRefIdx = n;
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

static CK_BBOOL isMechanismAvailable(STDLL_TokData_t *tokdata,
                                     CK_ULONG mechanism)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    unsigned int i;

    for (i = 0; i < ica_data->mech_list_len; i++) {
        if (ica_data->mech_list[i].mech_type == mechanism)
            return TRUE;
    }

    return FALSE;
}

static CK_BBOOL isMechanismHW(STDLL_TokData_t *tokdata, CK_ULONG mechanism)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    unsigned int i;

    for (i = 0; i < ica_data->mech_list_len; i++) {
        if (ica_data->mech_list[i].mech_type == mechanism)
            return ica_data->mech_list[i].mech_info.flags & CKF_HW;
    }

    return FALSE;
}

#define KEY_SIZE_512   0x01
#define KEY_SIZE_1024  0x02
#define KEY_SIZE_2048  0x04
#define KEY_SIZE_4096  0x08

#define RSA_NO_SMALL_EXP   0x00010000 /* e >= 65537 */

static void adjust_rsa_key_sizes(unsigned int mask,
                                 CK_MECHANISM_INFO *mech_info)
{
    CK_ULONG min = 0, max = 0;

    mask &= (KEY_SIZE_512 | KEY_SIZE_1024 | KEY_SIZE_2048 | KEY_SIZE_4096);
    if (mask == 0)
        return;

    if (mask & KEY_SIZE_512)
        min = 512;
    else if (mask & KEY_SIZE_1024)
        min = 1024;
    else if (mask & KEY_SIZE_2048)
        min = 2048;
    else if (mask & KEY_SIZE_4096)
        min = 4096;

    max = min;
    if (mask & KEY_SIZE_4096)
        max = 4096;
    else if (mask & KEY_SIZE_2048)
        max = 2048;
    else if (mask & KEY_SIZE_1024)
        max = 1024;
    else if (mask & KEY_SIZE_512)
        max = 512;

    if (min > mech_info->ulMinKeySize)
        mech_info->ulMinKeySize = min;
    if (max < mech_info->ulMaxKeySize)
        mech_info->ulMaxKeySize = max;
}

static CK_RV addMechanismToList(STDLL_TokData_t *tokdata, CK_ULONG mechanism,
                                CK_BBOOL hw, unsigned int rsa_keysize_mask)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_ULONG ret;
    CK_ULONG refIdx = 0;

    if (isMechanismAvailable(tokdata, mechanism))
        return CKR_OK;

    if (ica_data->mech_list_len >= ICA_MAX_MECH_LIST_ENTRIES) {
        TRACE_ERROR("Not enough slots available to add mechanism\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    ret = getRefListIdxfromMech(mechanism, &refIdx);
    if (ret != CKR_OK) {
        return CKR_FUNCTION_FAILED;
    }
    ica_data->mech_list[ica_data->mech_list_len].mech_type = ref_mech_list[refIdx].mech_type;
    ica_data->mech_list[ica_data->mech_list_len].mech_info.flags =
        (ref_mech_list[refIdx].mech_info.flags & (~CKF_HW)) | (hw ? CKF_HW : 0);
    ica_data->mech_list[ica_data->mech_list_len].mech_info.ulMinKeySize =
        ref_mech_list[refIdx].mech_info.ulMinKeySize;
    ica_data->mech_list[ica_data->mech_list_len].mech_info.ulMaxKeySize =
        ref_mech_list[refIdx].mech_info.ulMaxKeySize;

    adjust_rsa_key_sizes(rsa_keysize_mask,
                     &ica_data->mech_list[ica_data->mech_list_len].mech_info);

    ica_data->mech_list_len++;

    return CKR_OK;
}

/*
 * call libica to receive list of supported mechanisms
 * This method is called once per opencryptoki instance (application context)
 */
static CK_RV mech_list_ica_initialize(STDLL_TokData_t *tokdata)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_ULONG ret, rc = CKR_OK;
    unsigned int i, n, rsa_props = 0;
    unsigned int ica_specific_mech_list_len;
    CK_ULONG tmp, ulActMechCtr, ulPreDefMechCtr, refIdx;
    CK_BBOOL rsa_hw, ec_hw, sha_hw;

    /*
     * Add mechanisms where we have a SW fallback unconditionally, but only
     * if libica is not in FIPS mode. If libica is in FIPS mode, the loop below
     * will add those mechanisms that libica supports and that are FIPS
     * approved. Mechanisms that are not FIPS approved will not be added, even
     * if there is a SW fallback. Because the SW fallback is OpenSSL-based,
     * and OpenSSL is most likely also in FIPS mode in this case, the SW
     * fallback would also fail if using an algorithm that is not FIPS approved.
     */
    if (p_ica_fips_status == NULL || p_ica_fips_status() == 0) {
#if !(NOMD5)
        addMechanismToList(tokdata, CKM_MD5, 0, 0);
        addMechanismToList(tokdata, CKM_MD5_HMAC, 0, 0);
        addMechanismToList(tokdata, CKM_MD5_HMAC_GENERAL, 0, 0);
#endif

        /* We have RSA support (SW) in any case, regardless if libica supports it */
        addMechanismToList(tokdata, CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0);
        addMechanismToList(tokdata, CKM_RSA_PKCS, 0, 0);
#if !(NOX509)
        addMechanismToList(tokdata, CKM_RSA_X_509, 0, 0);
#endif

        /* We have EC support (SW) in any case, regardless if libica supports it */
        addMechanismToList(tokdata, CKM_EC_KEY_PAIR_GEN, 0, 0);
        addMechanismToList(tokdata, CKM_ECDSA, 0, 0);

        /* We have SHA support (SW) in any case, regardless if libica supports it */
        addMechanismToList(tokdata, CKM_SHA_1, 0, 0);
        addMechanismToList(tokdata, CKM_SHA224, 0, 0);
        addMechanismToList(tokdata, CKM_SHA256, 0, 0);
        addMechanismToList(tokdata, CKM_SHA384, 0, 0);
        addMechanismToList(tokdata, CKM_SHA512, 0, 0);
#ifdef NID_sha512_224WithRSAEncryption
        addMechanismToList(tokdata, CKM_SHA512_224, 0, 0);
#endif
#ifdef NID_sha512_256WithRSAEncryption
        addMechanismToList(tokdata, CKM_SHA512_256, 0, 0);
#endif
#ifdef NID_sha3_224
        addMechanismToList(tokdata, CKM_SHA3_224, 0, 0);
        addMechanismToList(tokdata, CKM_IBM_SHA3_224, 0, 0);
#endif
#ifdef NID_sha3_256
        addMechanismToList(tokdata, CKM_SHA3_256, 0, 0);
        addMechanismToList(tokdata, CKM_IBM_SHA3_256, 0, 0);
#endif
#ifdef NID_sha3_384
        addMechanismToList(tokdata, CKM_SHA3_384, 0, 0);
        addMechanismToList(tokdata, CKM_IBM_SHA3_384, 0, 0);
#endif
#ifdef NID_sha3_512
        addMechanismToList(tokdata, CKM_SHA3_512, 0, 0);
        addMechanismToList(tokdata, CKM_IBM_SHA3_512, 0, 0);
#endif

        /* We have AES support (SW) in any case, regardless if libica supports it */
        addMechanismToList(tokdata, CKM_AES_ECB, 0, 0);
        addMechanismToList(tokdata, CKM_AES_CBC, 0, 0);
        addMechanismToList(tokdata, CKM_AES_CBC_PAD, 0, 0);
        addMechanismToList(tokdata, CKM_AES_CTR, 0, 0);
#if OPENSSL_VERSION_PREREQ(3, 0) || OPENSSL_VERSION_NUMBER >= 0x101010cfL
        /*
         * AES-OFB/CFB currently only works with >= OpenSSl 3.0 or >= OpenSSL 1.1.1l,
         * due to a bug in OpenSSL <= 1.1.1k in s390x_aes_ofb_cipher() not updating
         * the IV in the context.
         */
        addMechanismToList(tokdata, CKM_AES_OFB, 0, 0);
        addMechanismToList(tokdata, CKM_AES_CFB8, 0, 0);
        /* CFB64 is not supported as SW fallback */
        addMechanismToList(tokdata, CKM_AES_CFB128, 0, 0);
#endif
        addMechanismToList(tokdata, CKM_AES_GCM, 0, 0);
        addMechanismToList(tokdata, CKM_AES_MAC, 0, 0);
        addMechanismToList(tokdata, CKM_AES_MAC_GENERAL, 0, 0);
        addMechanismToList(tokdata, CKM_AES_CMAC, 0, 0);
        addMechanismToList(tokdata, CKM_AES_CMAC_GENERAL, 0, 0);

        /* We have DES/3DES support (SW) in any case, regardless if libica supports it */
        addMechanismToList(tokdata, CKM_DES_ECB, 0, 0);
        addMechanismToList(tokdata, CKM_DES_CBC, 0, 0);
        addMechanismToList(tokdata, CKM_DES_CBC_PAD, 0, 0);
        addMechanismToList(tokdata, CKM_DES3_ECB, 0, 0);
        addMechanismToList(tokdata, CKM_DES3_CBC, 0, 0);
        addMechanismToList(tokdata, CKM_DES3_CBC_PAD, 0, 0);
        addMechanismToList(tokdata, CKM_DES_OFB64, 0, 0);
        addMechanismToList(tokdata, CKM_DES_CFB8, 0, 0);
        addMechanismToList(tokdata, CKM_DES_CFB64, 0, 0);
        addMechanismToList(tokdata, CKM_DES3_MAC, 0, 0);
        addMechanismToList(tokdata, CKM_DES3_MAC_GENERAL, 0, 0);
        addMechanismToList(tokdata, CKM_DES3_CMAC, 0, 0);
        addMechanismToList(tokdata, CKM_DES3_CMAC_GENERAL, 0, 0);
    }

    /*
     * We have RNG support (SW) in any case, regardless if libica supports it,
     * and independent of FIPS mode
     */
    addMechanismToList(tokdata, CKM_GENERIC_SECRET_KEY_GEN, 0, 0);
    addMechanismToList(tokdata, CKM_DES_KEY_GEN, 0, 0);
    addMechanismToList(tokdata, CKM_DES3_KEY_GEN, 0, 0);
    addMechanismToList(tokdata, CKM_AES_KEY_GEN, 0, 0);
    addMechanismToList(tokdata, CKM_AES_XTS_KEY_GEN, 0, 0);

    rc = ica_get_functionlist(NULL, &ica_specific_mech_list_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ica_get_functionlist failed\n");
        return CKR_FUNCTION_FAILED;
    }
    libica_func_list_element libica_func_list[ica_specific_mech_list_len];
    rc = ica_get_functionlist(libica_func_list, &ica_specific_mech_list_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ica_get_functionlist failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /*
     * grab the mechanism of the corresponding ID returned by libICA
     * from the internal reference list put the mechanism ID and the
     * HW support indication into an internal ica_mech_list and get
     * additional flag information from the reference list
     */
    ulPreDefMechCtr = ica_data->mech_list_len;
    for (i = 0; i < ica_specific_mech_list_len; i++) {

        if (libica_func_list[i].flags == 0)
            continue;

        /* Remember if libica supports RSA mechanisms (HW or SW) */
        if (libica_func_list[i].mech_mode_id == RSA_KEY_GEN_ME) {
            ica_data->ica_rsa_keygen_available = TRUE;
            if (libica_func_list[i].property != 0) {
                rsa_props = libica_func_list[i].property;
                ica_data->ica_rsa_no_small_pub_exp =
                        ((rsa_props & RSA_NO_SMALL_EXP) != 0);
            }
        }
        if (libica_func_list[i].mech_mode_id == RSA_ME) {
            ica_data->ica_rsa_endecrypt_available = TRUE;
            if (libica_func_list[i].property != 0)
                rsa_props = libica_func_list[i].property;
        }

        /* Remember if libica supports RNG mechanisms (HW or SW) */
        if (libica_func_list[i].mech_mode_id == P_RNG)
            ica_data->ica_p_rng_available = TRUE;

#ifndef NO_EC
        /* Remember if libica supports EC mechanisms (HW or SW) */
        if (ica_data->ica_ec_support_available) {
            if (libica_func_list[i].mech_mode_id == EC_KGEN)
                ica_data->ica_ec_keygen_available = TRUE;
            if (libica_func_list[i].mech_mode_id == EC_DSA_SIGN)
                ica_data->ica_ec_signverify_available = TRUE;
            if (libica_func_list[i].mech_mode_id == EC_DH)
                ica_data->ica_ec_derive_available = TRUE;
        }

        if (ica_data->ica_ec_edwards_support_available) {
            if (libica_func_list[i].mech_mode_id == ED25519_KEYGEN)
                ica_data->ica_ec_edwards_keygen_available = TRUE;
            if (libica_func_list[i].mech_mode_id == ED25519_SIGN)
                ica_data->ica_ec_edwards_signverify_available = TRUE;
        }
        if (ica_data->ica_ec_montgomery_support_available) {
            if (libica_func_list[i].mech_mode_id == X25519_KEYGEN)
                ica_data->ica_ec_montgomery_keygen_available = TRUE;
            if (libica_func_list[i].mech_mode_id == X25519_DERIVE)
                ica_data->ica_ec_montgomery_derive_available = TRUE;
        }
#endif

        /* Remember if libica supports SHA mechanisms (HW or SW) */
        if (libica_func_list[i].mech_mode_id == SHA1)
            ica_data->ica_sha1_available = TRUE;
        if (libica_func_list[i].mech_mode_id == SHA512)
            ica_data->ica_sha2_available = TRUE;
#ifdef SHA512_224
        if (libica_func_list[i].mech_mode_id == SHA512_224)
            ica_data->ica_sha512_224_available = TRUE;
#endif
#ifdef SHA512_256
        if (libica_func_list[i].mech_mode_id == SHA512_256)
            ica_data->ica_sha512_256_available = TRUE;
#endif
#ifdef SHA3_512
        if (libica_func_list[i].mech_mode_id == SHA3_512)
            ica_data->ica_sha3_available = TRUE;
#endif
#ifdef SHAKE256
        if (libica_func_list[i].mech_mode_id == SHAKE256)
            ica_data->ica_shake_available = TRUE;
#endif

        /* Remember if libica supports AES mechanisms (HW or SW) */
        if (libica_func_list[i].mech_mode_id == AES_CBC)
            ica_data->ica_aes_available = TRUE;

#ifdef AES_GCM_KMA
        /* Remember if libica supports the new AES-GCM API (z14 and later) */
        if (libica_func_list[i].mech_mode_id == AES_GCM_KMA)
            ica_data->ica_new_gcm_available = TRUE;
#endif

        /* Remember if libica supports DES/3DES mechanisms (HW or SW) */
        if (libica_func_list[i].mech_mode_id == DES_CBC)
            ica_data->ica_des_available = TRUE;
        if (libica_func_list[i].mech_mode_id == DES3_CBC)
            ica_data->ica_des3_available = TRUE;

        /* --- walk through the whole reflist and fetch all
         * matching mechanism's (if present) ---
         */
        refIdx = 0;
        while ((ret = getRefListIdxfromId(libica_func_list[i].mech_mode_id,
                                          &refIdx)) == CKR_OK) {
            /*
             * Loop over the predefined mechanism list and check
             * if we have to overrule a software implemented
             * mechanism from token by libica HW supported
             * mechanism.
             */
            for (n = 0, ulActMechCtr = (CK_ULONG)-1; n < ulPreDefMechCtr; n++) {
                if (ica_data->mech_list[n].mech_type ==
                                        ref_mech_list[refIdx].mech_type) {
                    ulActMechCtr = n;
                    break;
                }
            }
            if (ulActMechCtr == (CK_ULONG)(-1)) {
                /* add a new entry */
                if (ica_data->mech_list_len >= ICA_MAX_MECH_LIST_ENTRIES) {
                    TRACE_ERROR("Not enough slots available to add mechanism\n");
                    return CKR_BUFFER_TOO_SMALL;
                }
                ica_data->mech_list[ica_data->mech_list_len].mech_type =
                    ref_mech_list[refIdx].mech_type;
                ica_data->mech_list[ica_data->mech_list_len].mech_info.flags =
                    ((libica_func_list[i].flags & (ICA_FLAG_DHW | ICA_FLAG_SHW)) ? CKF_HW : 0) |
                    (ref_mech_list[refIdx].mech_info.flags & (~CKF_HW));
                ica_data->mech_list[ica_data->mech_list_len].mech_info.ulMinKeySize =
                    ref_mech_list[refIdx].mech_info.ulMinKeySize;
                ica_data->mech_list[ica_data->mech_list_len].mech_info.ulMaxKeySize =
                    ref_mech_list[refIdx].mech_info.ulMaxKeySize;

                if (libica_func_list[i].mech_mode_id == RSA_KEY_GEN_ME ||
                    libica_func_list[i].mech_mode_id == RSA_ME)
                    adjust_rsa_key_sizes(rsa_props,
                                     &ica_data->mech_list[ica_data->mech_list_len].mech_info);
                if (libica_func_list[i].mech_mode_id == AES_XTS &&
                    p_ica_aes_xts_ex == NULL)
                    ica_data->mech_list[ica_data->mech_list_len].mech_info.flags &= (~CKF_HW);

                ica_data->mech_list_len++;
            } else {
                /* replace existing entry */
                ica_data->mech_list[ulActMechCtr].mech_info.flags =
                    ((libica_func_list[i].flags & (ICA_FLAG_DHW | ICA_FLAG_SHW)) ? CKF_HW : 0) |
                    (ref_mech_list[refIdx].mech_info.flags & (~CKF_HW));

                if (libica_func_list[i].mech_mode_id == RSA_KEY_GEN_ME ||
                    libica_func_list[i].mech_mode_id == RSA_ME)
                    adjust_rsa_key_sizes(rsa_props,
                                     &ica_data->mech_list[ulActMechCtr].mech_info);
                if (libica_func_list[i].mech_mode_id == AES_XTS &&
                    p_ica_aes_xts_ex == NULL)
                    ica_data->mech_list[ulActMechCtr].mech_info.flags &= (~CKF_HW);
            }
            refIdx++;
        }
    }

    /*
     * check if special combined mechanisms are supported
     * if SHAnnn and RSA is available -> insert CKM_SHAnnn_RSA_PKCS[_PSS]
     * if MD2 and RSA is available    -> insert CKM_MD2_RSA_PKCS
     * if MD5 and RSA is available    -> insert CKM_MD5_RSA_PKCS
     * if SHAnnn and EC is available  -> insert CKM_ECDSA_SHAnnn
     * if SHAnnn and EC is available  -> insert CKM_ECDH1_DERIVE
     * if SHAnnn is available         -> insert CKM_SHAxxx_HMAC[_GENERAL]
     */
    rsa_hw = isMechanismHW(tokdata, CKM_RSA_PKCS);
    sha_hw = isMechanismHW(tokdata, CKM_SHA_1);
    if (isMechanismAvailable(tokdata, CKM_SHA_1) &&
        isMechanismAvailable(tokdata, CKM_SHA224) &&
        isMechanismAvailable(tokdata, CKM_SHA256) &&
        isMechanismAvailable(tokdata, CKM_SHA384) &&
        isMechanismAvailable(tokdata, CKM_SHA512)) {
        addMechanismToList(tokdata, CKM_RSA_PKCS_OAEP, 0, rsa_props);
        addMechanismToList(tokdata, CKM_RSA_PKCS_PSS, 0, rsa_props);
    }
    if (isMechanismAvailable(tokdata, CKM_SHA_1) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA1_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA224) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA224_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA256) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA256_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA384) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA384_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA512) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA512_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_224) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA3_224_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_256) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA3_256_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_384) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA3_384_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_512) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_SHA3_512_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
#if !(NOMD2 )
    if (isMechanismAvailable(tokdata, CKM_MD2) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_MD2_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
#endif
    if (isMechanismAvailable(tokdata, CKM_MD5) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS))
        addMechanismToList(tokdata, CKM_MD5_RSA_PKCS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA_1) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA1_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA224) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA224_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA256) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA256_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA384) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA384_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA512) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA512_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_224) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA3_224_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_256) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA3_256_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_384) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA3_384_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_SHA3_512) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_PSS))
        addMechanismToList(tokdata, CKM_SHA3_512_RSA_PKCS_PSS, rsa_hw && sha_hw, rsa_props);
    if (isMechanismAvailable(tokdata, CKM_AES_KEY_GEN) &&
        isMechanismAvailable(tokdata, CKM_RSA_PKCS_OAEP) &&
        isMechanismAvailable(tokdata, CKM_AES_KEY_WRAP_KWP))
        addMechanismToList(tokdata, CKM_RSA_AES_KEY_WRAP, 0, rsa_props);

    ec_hw = isMechanismHW(tokdata, CKM_ECDSA);
    if (isMechanismAvailable(tokdata, CKM_SHA_1) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA1, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA224) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA224, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA256) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA256, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA384) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA384, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA512) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA512, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_224) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA3_224, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_256) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA3_256, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_384) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA3_384, ec_hw && sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_512) &&
        isMechanismAvailable(tokdata, CKM_ECDSA))
        addMechanismToList(tokdata, CKM_ECDSA_SHA3_512, ec_hw && sha_hw, 0);

    if (isMechanismAvailable(tokdata, CKM_EC_KEY_PAIR_GEN) &&
        isMechanismAvailable(tokdata, CKM_SHA_1) &&
        isMechanismAvailable(tokdata, CKM_SHA224) &&
        isMechanismAvailable(tokdata, CKM_SHA256) &&
        isMechanismAvailable(tokdata, CKM_SHA384) &&
        isMechanismAvailable(tokdata, CKM_SHA512))
        addMechanismToList(tokdata, CKM_ECDH1_DERIVE, ec_hw && sha_hw, 0);

    if (isMechanismAvailable(tokdata, CKM_EC_KEY_PAIR_GEN) &&
        isMechanismAvailable(tokdata, CKM_ECDH1_DERIVE) &&
        isMechanismAvailable(tokdata, CKM_AES_KEY_WRAP_KWP))
        addMechanismToList(tokdata, CKM_ECDH_AES_KEY_WRAP, ec_hw && sha_hw, 0);

    if (isMechanismAvailable(tokdata, CKM_SHA_1)) {
        addMechanismToList(tokdata, CKM_SHA_1_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA_1_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA1_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA_1_KEY_GEN, sha_hw, 0);
    }
    if (isMechanismAvailable(tokdata, CKM_SHA224)) {
        addMechanismToList(tokdata, CKM_SHA224_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA224_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA224_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA224_KEY_GEN, sha_hw, 0);
    }
    if (isMechanismAvailable(tokdata, CKM_SHA256)) {
        addMechanismToList(tokdata, CKM_SHA256_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA256_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA256_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA256_KEY_GEN, sha_hw, 0);
    }
    if (isMechanismAvailable(tokdata, CKM_SHA384)) {
        addMechanismToList(tokdata, CKM_SHA384_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA384_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA384_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA384_KEY_GEN, sha_hw, 0);
    }
    if (isMechanismAvailable(tokdata, CKM_SHA512)) {
        addMechanismToList(tokdata, CKM_SHA512_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_KEY_GEN, sha_hw, 0);
    }
#ifdef NID_sha512_224WithRSAEncryption
    if (isMechanismAvailable(tokdata, CKM_SHA512_224)) {
        addMechanismToList(tokdata, CKM_SHA512_224_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_224_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_224_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_224_KEY_GEN, sha_hw, 0);
    }
#endif
#ifdef NID_sha512_256WithRSAEncryption
    if (isMechanismAvailable(tokdata, CKM_SHA512_256)) {
        addMechanismToList(tokdata, CKM_SHA512_256_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_256_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_256_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA512_256_KEY_GEN, sha_hw, 0);
    }
#endif
#ifdef NID_sha3_224
    if (isMechanismAvailable(tokdata, CKM_IBM_SHA3_224))
        addMechanismToList(tokdata, CKM_IBM_SHA3_224_HMAC, sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_224)) {
        addMechanismToList(tokdata, CKM_SHA3_224_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_224_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_224_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_224_KEY_GEN, sha_hw, 0);
    }
#endif
#ifdef NID_sha3_256
    if (isMechanismAvailable(tokdata, CKM_IBM_SHA3_256))
        addMechanismToList(tokdata, CKM_IBM_SHA3_256_HMAC, sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_256)) {
        addMechanismToList(tokdata, CKM_SHA3_256_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_256_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_256_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_256_KEY_GEN, sha_hw, 0);
    }
#endif
#ifdef NID_sha3_384
    if (isMechanismAvailable(tokdata, CKM_IBM_SHA3_384))
        addMechanismToList(tokdata, CKM_IBM_SHA3_384_HMAC, sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_384)) {
        addMechanismToList(tokdata, CKM_SHA3_384_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_384_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_384_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_384_KEY_GEN, sha_hw, 0);
    }
#endif
#ifdef NID_sha3_512
    if (isMechanismAvailable(tokdata, CKM_IBM_SHA3_512))
        addMechanismToList(tokdata, CKM_IBM_SHA3_512_HMAC, sha_hw, 0);
    if (isMechanismAvailable(tokdata, CKM_SHA3_512)) {
        addMechanismToList(tokdata, CKM_SHA3_512_HMAC, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_512_HMAC_GENERAL, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_512_KEY_DERIVATION, sha_hw, 0);
        addMechanismToList(tokdata, CKM_SHA3_512_KEY_GEN, sha_hw, 0);
    }
#endif

    /* sort the mech_list_ica by mechanism ID's (bubble sort)  */
    for (i = 0; i < ica_data->mech_list_len; i++) {
        for (n = i; n < ica_data->mech_list_len; n++) {
            if (ica_data->mech_list[i].mech_type > ica_data->mech_list[n].mech_type) {
                tmp = ica_data->mech_list[i].mech_type;
                ica_data->mech_list[i].mech_type = ica_data->mech_list[n].mech_type;
                ica_data->mech_list[n].mech_type = tmp;

                tmp = ica_data->mech_list[i].mech_info.ulMinKeySize;
                ica_data->mech_list[i].mech_info.ulMinKeySize =
                        ica_data->mech_list[n].mech_info.ulMinKeySize;
                ica_data->mech_list[n].mech_info.ulMinKeySize = tmp;

                tmp = ica_data->mech_list[i].mech_info.ulMaxKeySize;
                ica_data->mech_list[i].mech_info.ulMaxKeySize =
                        ica_data->mech_list[n].mech_info.ulMaxKeySize;
                ica_data->mech_list[n].mech_info.ulMaxKeySize = tmp;

                tmp = ica_data->mech_list[i].mech_info.flags;
                ica_data->mech_list[i].mech_info.flags = ica_data->mech_list[n].mech_info.flags;
                ica_data->mech_list[n].mech_info.flags = tmp;
            }
        }
    }

    return rc;
}

CK_RV token_specific_generic_secret_key_gen(STDLL_TokData_t *tokdata,
                                            TEMPLATE *tmpl)
{
    CK_RV rc = CKR_OK;
    CK_BYTE secret_key[MAX_GENERIC_KEY_SIZE];
    CK_ULONG key_length = 0;
    CK_ULONG key_length_in_bits = 0;
    CK_ATTRIBUTE *value_attr = NULL;

    rc = template_attribute_get_ulong(tmpl, CKA_VALUE_LEN, &key_length);
    if (rc != CKR_OK) {
        TRACE_ERROR("CKA_VALUE_LEN missing in (HMAC) key template\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    //app specified key length in bytes
    key_length_in_bits = key_length * 8;

    /* After looking at fips cavs test vectors for HMAC ops,
     * it was decided that the key length should fall between
     * 80 and 2048 bits inclusive.
     */
    if ((key_length_in_bits < 80) || (key_length_in_bits > 2048)) {
        TRACE_ERROR("Generic secret key size of %lu bits not within"
                    " required range of 80-2048 bits\n", key_length_in_bits);
        return CKR_KEY_SIZE_RANGE;
    }

    /* libica does not have generic secret key generation,
     * so call token rng here.
     */
    rc = rng_generate(tokdata, secret_key, key_length);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Generic secret key generation failed.\n");
        return rc;
    }

    rc = build_attribute(CKA_VALUE, secret_key, key_length, &value_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_VALUE) failed\n");
        return rc;
    }
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute(CKA_VALUE) failed\n");
        free(value_attr);
    }

    return rc;
}

#ifndef NO_EC
static CK_RV build_update_attribute(TEMPLATE *tmpl,
                                    CK_ATTRIBUTE_TYPE type,
                                    CK_BYTE *data, CK_ULONG data_len)
{
    CK_ATTRIBUTE *attr;
    CK_RV rv;

    if ((rv = build_attribute(type, data, data_len, &attr)))
        return rv;

    rv = template_update_attribute(tmpl, attr);
    if (rv != CKR_OK) {
        free(attr);
        return rv;
    }

    return CKR_OK;
}

static CK_RV is_equal(unsigned char *a,
                      unsigned int a_length,
                      unsigned char *b, unsigned int b_length)
{
    if (a_length != b_length)
        return 0;

    if (memcmp(a, b, a_length) == 0)
        return 1;

    return 0;
}

static int nid_from_oid(CK_BYTE *oid, CK_ULONG oid_length)
{
    /* Supported Elliptic Curves */
    static const CK_BYTE brainpoolP160r1[] =
        { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };
    static const CK_BYTE brainpoolP192r1[] =
        { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03 };
    static const CK_BYTE brainpoolP224r1[] =
        { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05 };
    static const CK_BYTE brainpoolP256r1[] =
        { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
    static const CK_BYTE brainpoolP320r1[] =
        { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09 };
    static const CK_BYTE brainpoolP384r1[] =
        { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B };
    static const CK_BYTE brainpoolP512r1[] =
        { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D };
    static const CK_BYTE prime192[] =
        { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };
    static const CK_BYTE secp224[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 };
    static const CK_BYTE prime256[] =
        { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    static const CK_BYTE secp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
    static const CK_BYTE secp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
    static const CK_BYTE curve25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x6E };
    static const CK_BYTE curve448[] = { 0x06, 0x03, 0x2B, 0x65, 0x6F };
    static const CK_BYTE ed25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
    static const CK_BYTE ed448[] = { 0x06, 0x03, 0x2B, 0x65, 0x71 };

    if (is_equal
        (oid, oid_length, (unsigned char *) &prime192, sizeof(prime192)))
        return NID_X9_62_prime192v1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &secp224, sizeof(secp224)))
        return NID_secp224r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &prime256, sizeof(prime256)))
        return NID_X9_62_prime256v1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &secp384, sizeof(secp384)))
        return NID_secp384r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &secp521, sizeof(secp521)))
        return NID_secp521r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &brainpoolP160r1,
                      sizeof(brainpoolP160r1)))
        return NID_brainpoolP160r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &brainpoolP192r1,
                      sizeof(brainpoolP192r1)))
        return NID_brainpoolP192r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &brainpoolP224r1,
                      sizeof(brainpoolP224r1)))
        return NID_brainpoolP224r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &brainpoolP256r1,
                      sizeof(brainpoolP256r1)))
        return NID_brainpoolP256r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &brainpoolP320r1,
                      sizeof(brainpoolP320r1)))
        return NID_brainpoolP320r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &brainpoolP384r1,
                      sizeof(brainpoolP384r1)))
        return NID_brainpoolP384r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &brainpoolP512r1,
                      sizeof(brainpoolP512r1)))
        return NID_brainpoolP512r1;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &curve25519,
                      sizeof(curve25519)))
        return NID_X25519;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &curve448,
                      sizeof(curve448)))
        return NID_X448;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &ed25519,
                      sizeof(ed25519)))
        return NID_ED25519;
    else if (is_equal(oid, oid_length,
                      (unsigned char *) &ed448,
                      sizeof(ed448)))
        return NID_ED448;

    return -1;
}

static CK_RV ica_specific_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                              TEMPLATE *publ_tmpl,
                                              TEMPLATE *priv_tmpl)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    ICA_EC_KEY *eckey;
    CK_BYTE q_array[1 + ICATOK_EC_MAX_Q_LEN];
    CK_BYTE d_array[ICATOK_EC_MAX_D_LEN];
    unsigned int privlen, q_len, d_len;
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len;
    int rc, nid;

    if (!ica_data->ica_ec_support_available) {
        TRACE_ERROR("ECC support is not available in Libica\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    ret = template_attribute_get_non_empty(publ_tmpl, CKA_EC_PARAMS, &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Determine curve nid */
    nid = nid_from_oid(attr->pValue, attr->ulValueLen);
    if (nid < 0) {
        TRACE_ERROR("curve not supported by icatoken.\n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    /* Create ICA_EC_KEY object */
    eckey = p_ica_ec_key_new(nid, &privlen);
    if (!eckey) {
        TRACE_ERROR("ica_ec_key_new() failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Generate key data for this key object */
    rc = p_ica_ec_key_generate(ica_data->adapter_handle, eckey);
    if (rc != 0) {
        switch (rc) {
        case EPERM:
            TRACE_ERROR("ica_ec_key_generate() failed with rc=EPERM, probably curve not supported by openssl.\n");
            ret = CKR_CURVE_NOT_SUPPORTED;
            break;
        case ENODEV:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            ret = CKR_FUNCTION_FAILED;
            break;
        }
        goto end;
    }

    /* Return public key (X,Y) via CKA_EC_POINT as OCTET STRING */
    rc = p_ica_ec_key_get_public_key(eckey, (unsigned char *)&q_array[1],
                                     &q_len);
    if (rc != 0) {
        TRACE_ERROR("ica_ec_key_get_public_key() failed with rc=%d.\n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    q_array[0] = POINT_CONVERSION_UNCOMPRESSED;
    q_len++;

    rc = ber_encode_OCTET_STRING(FALSE, &ecpoint, &ecpoint_len, q_array, q_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
        goto end;
    }

    ret = build_update_attribute(publ_tmpl, CKA_EC_POINT, ecpoint, ecpoint_len);
    if (ret != 0) {
        TRACE_ERROR("build_update_attribute for (X,Y) failed rc=0x%lx\n", ret);
        goto end;
    }

    /* Return private key (D) via CKA_VALUE */
    rc = p_ica_ec_key_get_private_key(eckey, (unsigned char *) &d_array,
                                      &d_len);
    if (rc != 0) {
        TRACE_ERROR("ica_ec_key_get_private_key() failed with rc=%d.\n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    ret = build_update_attribute(priv_tmpl, CKA_VALUE, d_array, d_len);
    if (ret != 0) {
        TRACE_ERROR("build_update_attribute for (D) failed, rc=0x%lx\n", ret);
        goto end;
    }

    /* Add CKA_EC_PARAMS to private template also */
    ret = build_update_attribute(priv_tmpl, CKA_EC_PARAMS, attr->pValue,
                                 attr->ulValueLen);
    if (ret != 0) {
        TRACE_ERROR("build_update_attribute for CKA_EC_PARAMS failed, "
                    "rc=0x%lx\n", ret);
        goto end;
    }

    ret = CKR_OK;

end:
    p_ica_ec_key_free(eckey);
    if (ecpoint != NULL)
        free(ecpoint);

    return ret;
}

CK_RV token_specific_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                         TEMPLATE *publ_tmpl,
                                         TEMPLATE *priv_tmpl)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_ec_keygen_available) {
        rc = ica_specific_ec_generate_keypair(tokdata, publ_tmpl, priv_tmpl);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_keygen_available = FALSE;
    }

    if (!ica_data->ica_ec_keygen_available)
        rc = openssl_specific_ec_generate_keypair(tokdata, publ_tmpl,
                                                  priv_tmpl,
                                                  CKM_EC_KEY_PAIR_GEN);

    return rc;
}

static int ica_ed_x_ctx_new(int nid, void **ctx)
{
    switch (nid) {
    case NID_ED25519:
        return p_ica_ed25519_ctx_new((ICA_ED25519_CTX**)ctx);
    case NID_ED448:
        return p_ica_ed448_ctx_new((ICA_ED448_CTX**)ctx);
    case NID_X25519:
        return p_ica_x25519_ctx_new((ICA_X25519_CTX**)ctx);
    case NID_X448:
        return p_ica_x448_ctx_new((ICA_X448_CTX**)ctx);
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static int ica_ed_x_ctx_del(int nid, void **ctx)
{
    switch (nid) {
    case NID_ED25519:
        return p_ica_ed25519_ctx_del((ICA_ED25519_CTX**)ctx);
    case NID_ED448:
        return p_ica_ed448_ctx_del((ICA_ED448_CTX**)ctx);
    case NID_X25519:
        return p_ica_x25519_ctx_del((ICA_X25519_CTX**)ctx);
    case NID_X448:
        return p_ica_x448_ctx_del((ICA_X448_CTX**)ctx);
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static int ica_ed_x_key_gen(int nid, void *ctx)
{
    switch (nid) {
    case NID_ED25519:
        return p_ica_ed25519_key_gen((ICA_ED25519_CTX*)ctx);
    case NID_ED448:
        return p_ica_ed448_key_gen((ICA_ED448_CTX*)ctx);
    case NID_X25519:
        return p_ica_x25519_key_gen((ICA_X25519_CTX*)ctx);
    case NID_X448:
        return p_ica_x448_key_gen((ICA_X448_CTX*)ctx);
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static int ica_ed_x_key_get(int nid, void *ctx, CK_BYTE* priv,
                            CK_BYTE *pub, CK_ULONG *len)
{
    switch (nid) {
    case NID_ED25519:
        if (*len < 32)
            return EINVAL;
        *len = 32;
        return p_ica_ed25519_key_get((ICA_ED25519_CTX*)ctx, priv, pub);
    case NID_ED448:
        if (*len < 57)
            return EINVAL;
        *len = 57;
        return p_ica_ed448_key_get((ICA_ED448_CTX*)ctx, priv, pub);
    case NID_X25519:
        if (*len < 32)
            return EINVAL;
        *len = 32;
        return p_ica_x25519_key_get((ICA_X25519_CTX*)ctx, priv, pub);
    case NID_X448:
        if (*len < 56)
            return EINVAL;
        *len = 56;
        return p_ica_x448_key_get((ICA_X448_CTX*)ctx, priv, pub);
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static int ica_ed_x_key_set(int nid, void *ctx, CK_BYTE* priv,
                            CK_BYTE *pub, CK_ULONG len)
{
    switch (nid) {
    case NID_ED25519:
        if (len != 32)
            return EINVAL;
        return p_ica_ed25519_key_set((ICA_ED25519_CTX*)ctx, priv, pub);
    case NID_ED448:
        if (len != 57)
            return EINVAL;
        return p_ica_ed448_key_set((ICA_ED448_CTX*)ctx, priv, pub);
    case NID_X25519:
        if (len != 32)
            return EINVAL;
        return p_ica_x25519_key_set((ICA_X25519_CTX*)ctx, priv, pub);
    case NID_X448:
        if (len != 56)
            return EINVAL;
        return p_ica_x448_key_set((ICA_X448_CTX*)ctx, priv, pub);
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static int ica_eddsa_sign(int nid, void *ctx, CK_BYTE *sig, CK_ULONG *sig_len,
                          CK_BYTE *msg, CK_ULONG msg_len)
{
    switch (nid) {
    case NID_ED25519:
        if (*sig_len < 64)
            return EINVAL;
        *sig_len = 64;
        return p_ica_ed25519_sign((ICA_ED25519_CTX*)ctx, sig, msg, msg_len);
    case NID_ED448:
        if (*sig_len < 114)
            return EINVAL;
        *sig_len = 114;
        return p_ica_ed448_sign((ICA_ED448_CTX*)ctx, sig, msg, msg_len);
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static int ica_eddsa_verify(int nid, void *ctx, CK_BYTE *sig, CK_ULONG sig_len,
                            CK_BYTE *msg, CK_ULONG msg_len)
{
    switch (nid) {
    case NID_ED25519:
        if (sig_len != 64)
            return EINVAL;
        return p_ica_ed25519_verify((ICA_ED25519_CTX*)ctx, sig, msg, msg_len);
    case NID_ED448:
        if (sig_len != 114)
            return EINVAL;
        return p_ica_ed448_verify((ICA_ED448_CTX*)ctx, sig, msg, msg_len);
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static int ica_x_derive(int nid, void *ctx, CK_BYTE *shared_secret,
                        CK_BYTE *peer_pubkey, CK_ULONG key_len)
{
    switch (nid) {
    case NID_X25519:
        if (key_len != 32)
            return EINVAL;
        return p_ica_x25519_derive((ICA_X25519_CTX*)ctx, shared_secret,
                                   peer_pubkey);
    case NID_X448:
        if (key_len != 56)
            return EINVAL;
        return p_ica_x448_derive((ICA_X448_CTX*)ctx, shared_secret,
                                 peer_pubkey);
        break;
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return EPERM;
    }
}

static CK_RV ica_specific_ec_edwards_montgomery_generate_keypair(
                                                      STDLL_TokData_t *tokdata,
                                                      TEMPLATE *publ_tmpl,
                                                      TEMPLATE *priv_tmpl,
                                                      CK_MECHANISM_TYPE mech)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    void *ctx = NULL;
    CK_BYTE priv[57], pub [57];
    CK_ULONG key_len = sizeof(priv);
    int rc, nid;

    ret = template_attribute_get_non_empty(publ_tmpl, CKA_EC_PARAMS, &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Determine curve nid */
    nid = nid_from_oid(attr->pValue, attr->ulValueLen);
    if (nid < 0) {
        TRACE_ERROR("curve not supported by icatoken.\n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    switch (nid) {
    case NID_ED25519:
    case NID_ED448:
        if (mech != CKM_EC_EDWARDS_KEY_PAIR_GEN) {
            TRACE_ERROR("Edwards curve only supported with "
                        "CKM_EC_EDWARDS_KEY_PAIR_GEN.\n");
            return CKR_CURVE_NOT_SUPPORTED;
        }
        if (!ica_data->ica_ec_edwards_keygen_available) {
            TRACE_ERROR("EC-Edwards support is not available in Libica\n");
            return CKR_FUNCTION_NOT_SUPPORTED;
        }
        break;
    case NID_X25519:
    case NID_X448:
        if (mech != CKM_EC_MONTGOMERY_KEY_PAIR_GEN) {
            TRACE_ERROR("Montgomery curve only supported with "
                        "CKM_EC_MONTGOMERY_KEY_PAIR_GEN.\n");
            return CKR_CURVE_NOT_SUPPORTED;
        }
        if (!ica_data->ica_ec_montgomery_keygen_available) {
            TRACE_ERROR("EC-Montgomery support is not available in Libica\n");
            return CKR_FUNCTION_NOT_SUPPORTED;
        }
        break;
    default:
        TRACE_ERROR("Not an Edwards or Montgomery curve.\n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    /* Create ICA_ED/Xxxx_CTX object */
    rc = ica_ed_x_ctx_new(nid, &ctx);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_ctx_new failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Generate key data for this key object */
    rc = ica_ed_x_key_gen(nid, ctx);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_key_gen() failed with rc = %d \n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    /* Get the key material */
    rc = ica_ed_x_key_get(nid, ctx, priv, pub, &key_len);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_key_get failed with rc=%d.\n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    /* Return public key (X, Y) via CKA_EC_POINT */
    ret = build_update_attribute(publ_tmpl, CKA_EC_POINT, pub, key_len);
    if (ret != 0) {
        TRACE_ERROR("build_update_attribute for (X,Y) failed rc=0x%lx\n", ret);
        goto end;
    }

    /* Return private key (D) via CKA_VALUE */
    ret = build_update_attribute(priv_tmpl, CKA_VALUE, priv, key_len);
    if (ret != 0) {
        TRACE_ERROR("build_update_attribute for (D) failed, rc=0x%lx\n", ret);
        goto end;
    }

    /* Add CKA_EC_PARAMS to private template also */
    ret = build_update_attribute(priv_tmpl, CKA_EC_PARAMS, attr->pValue,
                                 attr->ulValueLen);
    if (ret != 0) {
        TRACE_ERROR("build_update_attribute for CKA_EC_PARAMS failed, "
                    "rc=0x%lx\n", ret);
        goto end;
    }

    ret = CKR_OK;

end:
    ica_ed_x_ctx_del(nid, &ctx);

    return ret;

}

CK_RV token_specific_ec_edwards_generate_keypair(STDLL_TokData_t *tokdata,
                                                 TEMPLATE *publ_tmpl,
                                                 TEMPLATE *priv_tmpl)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_ec_edwards_keygen_available) {
        rc = ica_specific_ec_edwards_montgomery_generate_keypair(
                                            tokdata, publ_tmpl, priv_tmpl,
                                            CKM_EC_EDWARDS_KEY_PAIR_GEN);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_edwards_keygen_available = FALSE;
    }

    if (!ica_data->ica_ec_edwards_keygen_available)
        rc = openssl_specific_ec_generate_keypair(tokdata, publ_tmpl,
                                                  priv_tmpl,
                                                  CKM_EC_EDWARDS_KEY_PAIR_GEN);

    return rc;
}

CK_RV token_specific_ec_montgomery_generate_keypair(STDLL_TokData_t *tokdata,
                                                    TEMPLATE *publ_tmpl,
                                                    TEMPLATE *priv_tmpl)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_ec_montgomery_keygen_available) {
        rc = ica_specific_ec_edwards_montgomery_generate_keypair(
                                                tokdata, publ_tmpl, priv_tmpl,
                                                CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_montgomery_keygen_available = FALSE;
    }

    if (!ica_data->ica_ec_montgomery_keygen_available)
        rc = openssl_specific_ec_generate_keypair(tokdata, publ_tmpl,
                                                  priv_tmpl,
                                                  CKM_EC_MONTGOMERY_KEY_PAIR_GEN);

    return rc;
}

/**
 * decompress the given compressed public key. Sets x from given pub_key,
 * re-calculates y from format byte, x and nid.
 *
 * @return 0 on success
 */
static CK_RV decompress_pubkey(unsigned int nid,
                               const unsigned char *pub_key,
                               CK_ULONG pub_len,
                               unsigned int priv_len,
                               unsigned char *x, unsigned char *y)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_x = BN_bin2bn((unsigned char *) &(pub_key[1]), priv_len, NULL);
    BIGNUM *bn_y = BN_new();
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    int y_bit = (pub_key[0] == POINT_CONVERSION_COMPRESSED ? 0 : 1);
    CK_RV ret = CKR_OK;

    UNUSED(pub_len);

    group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        TRACE_ERROR("Curve %d is not supported by openssl. Cannot decompress "
                    "public key\n", nid);
        ret = CKR_CURVE_NOT_SUPPORTED;
        goto end;
    }

    point = EC_POINT_new(group);
    if (!point) {
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    if (!EC_POINT_set_compressed_coordinates(group,
                                             point, bn_x, y_bit, ctx)) {
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    if (!EC_POINT_is_on_curve(group, point, ctx)) {
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    if (!EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y, ctx)) {
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    memcpy(x, &(pub_key[1]), priv_len);
    BN_bn2bin(bn_y, y);

end:
    if (ctx)
        BN_CTX_free(ctx);
    if (point)
        EC_POINT_free(point);
    if (group)
        EC_GROUP_free(group);
    if (bn_x)
        BN_free(bn_x);
    if (bn_y)
        BN_free(bn_y);

    return ret;
}

/**
 * returns the (X,Y) coordinates of the given EC public key.
 * For a compressed key, Y is calculated from X and an indication
 * if Y is even or odd.
 *
 * Refer to X9.62, section 4.3.6, "point to octet-string conversion".
 *
 * @return 0 on success
 */
static CK_RV set_pubkey_coordinates(unsigned int nid,
                                    const unsigned char *pub_key,
                                    CK_ULONG pub_len,
                                    unsigned int priv_len,
                                    unsigned char *x, unsigned char *y)
{
    int i, n;

    /* Check if key has no format byte: [X || Y] */
    if (pub_len == 2 * priv_len) {
        memcpy(x, pub_key, priv_len);
        memcpy(y, pub_key + priv_len, priv_len);
        return CKR_OK;
    }

    /* Check if key is compressed: [0x0n || X]
     *   0x0n: 0x02: Y is even
     *         0x03: Y is odd
     */
    if (pub_len == priv_len + 1 &&
        (pub_key[0] == POINT_CONVERSION_COMPRESSED ||
         pub_key[0] == POINT_CONVERSION_COMPRESSED + 1)) {
        return decompress_pubkey(nid, pub_key, pub_len, priv_len, x, y);
    }

    /* Check if key is uncompressed or hybrid: [0x0n || X || Y]
     *   0x0n: 0x04 : uncompressed
     *         0c06 : hybrid, Y is even
     *         0x07 : hybrid, Y is odd
     */
    if (pub_len == 2 * priv_len + 1 &&
        (pub_key[0] == POINT_CONVERSION_UNCOMPRESSED ||
         pub_key[0] == POINT_CONVERSION_HYBRID ||
         pub_key[0] == POINT_CONVERSION_HYBRID + 1)) {
        memcpy(x, pub_key + 1, priv_len);
        memcpy(y, pub_key + 1 + priv_len, priv_len);
        return CKR_OK;
    }

    /* Add leading null bytes to pub_key X, if necessary. In this
     * case there is no format byte */
    if (pub_len < 2 * priv_len) {
        n = 2 * priv_len - pub_len;
        for (i = 0; i < n; i++)
            x[i] = 0x00;
        memcpy(x + i, pub_key, priv_len - n);
        memcpy(y, pub_key + priv_len - n, priv_len);
        return CKR_OK;
    }

    memset(x, 0, priv_len);
    memset(y, 0, priv_len);

    return CKR_FUNCTION_FAILED;
}

static CK_RV ica_prepare_ec_key(OBJECT *key_obj, ICA_EC_KEY **eckey,
                                unsigned int *privlen, int *nid)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr;

    /* Get CKA_EC_PARAMS from template */
    ret = template_attribute_get_non_empty(key_obj->template, CKA_EC_PARAMS,
                                           &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Determine curve nid */
    *nid = nid_from_oid(attr->pValue, attr->ulValueLen);
    if (*nid < 0) {
        TRACE_ERROR("Cannot determine curve nid. \n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    /* Create ICA_EC_KEY object */
    *eckey = p_ica_ec_key_new(*nid, privlen);
    if (!*eckey) {
        TRACE_ERROR("ica_ec_key_new() failed for curve %i.\n", *nid);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV ica_build_ec_priv_key(OBJECT *key_obj, ICA_EC_KEY **eckey,
                                   unsigned int *privlen)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr;
    unsigned char *d = NULL;
    int rc, nid;

    /* Prepare the ICA key */
    ret = ica_prepare_ec_key(key_obj, eckey, privlen, &nid);
    if (ret != CKR_OK) {
        TRACE_ERROR("ica_prepare_ec_key() failed with rc = 0x%lx. \n", ret);
        return ret;
    }

    /* Get private key from template via CKA_VALUE */
    ret = template_attribute_get_non_empty(key_obj->template, CKA_VALUE,
                                           &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        ret = CKR_TEMPLATE_INCOMPLETE;
        goto end;
    }

    /* Add zero padding if needed */
    if (*privlen > attr->ulValueLen) {
        d = calloc(*privlen, 1);
        if (d == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            ret = CKR_HOST_MEMORY;
            goto end;
        }

        memcpy(d + *privlen - attr->ulValueLen, attr->pValue,
               attr->ulValueLen);
    }

    /* Initialize ICA_EC_KEY with private key (D) */
    rc = p_ica_ec_key_init(NULL, NULL, d != NULL ? d : attr->pValue, *eckey);
    if (rc != 0) {
        switch (rc) {
        case ENODEV:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
        case EPERM:
            TRACE_ERROR("ica_ec_key_init() failed with rc=EPERM, probably curve not supported by openssl.\n");
            ret = CKR_CURVE_NOT_SUPPORTED;
            break;
        default:
            TRACE_ERROR("ica_ec_key_init() failed with rc = %d \n", rc);
            ret = CKR_FUNCTION_FAILED;
            break;
        }
        goto end;
    }

end:
    if (ret != CKR_OK) {
        p_ica_ec_key_free(*eckey);
        *eckey = NULL;
    }
    if (d != NULL)
        free(d);

    return ret;
}

static CK_RV ica_build_ec_pub_key(OBJECT *key_obj, ICA_EC_KEY **eckey,
                                  unsigned int *privlen)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr;
    unsigned char x_array[ICATOK_EC_MAX_D_LEN];
    unsigned char y_array[ICATOK_EC_MAX_D_LEN];
    int rc, nid;
    CK_BYTE *ecpoint;
    CK_ULONG ecpoint_len, field_len;

    /* Prepare the ICA key */
    ret = ica_prepare_ec_key(key_obj, eckey, privlen, &nid);
    if (ret != CKR_OK) {
        TRACE_ERROR("ica_prepare_ec_key() failed with rc = 0x%lx. \n", ret);
        return ret;
    }

    /* Get public key (X,Y) from template via CKA_EC_POINT */
    ret = template_attribute_get_non_empty(key_obj->template, CKA_EC_POINT,
                                           &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        ret = CKR_TEMPLATE_INCOMPLETE;
        goto end;
    }

    /* CKA_EC_POINT contains the EC point as OCTET STRING */
    ret = ber_decode_OCTET_STRING(attr->pValue, &ecpoint, &ecpoint_len,
                                  &field_len);
    if (ret != CKR_OK || field_len != attr->ulValueLen) {
        TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
        ret = CKR_ATTRIBUTE_VALUE_INVALID;
        goto end;
    }

    /* Provide (X,Y), decompress key if necessary */
    ret = set_pubkey_coordinates(nid, ecpoint, ecpoint_len,
                                 *privlen, x_array, y_array);
    if (ret != 0) {
        TRACE_ERROR("Cannot determine public key coordinates from "
                    "given public key\n");
        goto end;
    }

    /* Initialize ICA_EC_KEY with public key (Q) */
    rc = p_ica_ec_key_init(x_array, y_array, NULL, *eckey);
    if (rc != 0) {
        switch (rc) {
        case ENODEV:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
        case EPERM:
            TRACE_ERROR("ica_ec_key_init() failed with rc=EPERM, probably curve not supported by openssl.\n");
            ret = CKR_CURVE_NOT_SUPPORTED;
            break;
        default:
            TRACE_ERROR("ica_ec_key_init() failed with rc = %d \n", rc);
            ret = CKR_FUNCTION_FAILED;
            break;
        }
        goto end;
    }

end:
    if (ret != CKR_OK) {
        p_ica_ec_key_free(*eckey);
        *eckey = NULL;
    }

    return ret;
}

static CK_RV ica_specific_ec_sign(STDLL_TokData_t *tokdata,  SESSION *sess,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *out_data, CK_ULONG *out_data_len,
                                  OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    ica_ex_data_t *ex_data = NULL;
    CK_RV ret = CKR_OK;
    ICA_EC_KEY *eckey;
    unsigned int privlen;
    int rc;

    UNUSED(sess);

    *out_data_len = 0;

    if (!ica_data->ica_ec_support_available) {
        TRACE_ERROR("ECC support is not available in Libica\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(ica_ex_data_t),
                             ica_need_wr_lock_ec_key, ica_free_ex_data);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->eckey == NULL) {
        /* Get the private key */
        ret = ica_build_ec_priv_key(key_obj, &ex_data->eckey,
                                             &ex_data->ec_privlen);
        if (ret != CKR_OK) {
            TRACE_ERROR("ica_build_ec_priv_key() failed with rc = 0x%lx. \n",
                        ret);
            goto end;
        }
    }

    eckey = ex_data->eckey;
    privlen = ex_data->ec_privlen;

    /* Create signature */
    rc = p_ica_ecdsa_sign(ica_data->adapter_handle, eckey,
                          (unsigned char *) in_data,
                          (unsigned int) in_data_len,
                          (unsigned char *) out_data, 2 * privlen);
    if (rc != 0) {
        switch (rc) {
        case ENODEV:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
        default:
            TRACE_ERROR("ica_ecdsa_sign() failed with rc = %d. \n", rc);
            ret = CKR_FUNCTION_FAILED;
            break;
        }
        goto end;
    }

    *out_data_len = 2 * privlen;
    ret = CKR_OK;

end:
    object_ex_data_unlock(key_obj);

    return ret;
}

CK_RV token_specific_ec_sign(STDLL_TokData_t *tokdata,  SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_ec_signverify_available) {
        rc = ica_specific_ec_sign(tokdata, sess, in_data, in_data_len,
                                  out_data, out_data_len, key_obj);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_signverify_available = FALSE;
    }

    if (!ica_data->ica_ec_signverify_available)
        rc = openssl_specific_ec_sign(tokdata, sess, in_data, in_data_len,
                                      out_data, out_data_len, key_obj);

    return rc;
}

static CK_RV ica_specific_ec_verify(STDLL_TokData_t *tokdata,
                                    SESSION *sess,
                                    CK_BYTE *in_data,
                                    CK_ULONG in_data_len,
                                    CK_BYTE *signature,
                                    CK_ULONG signature_len, OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    ica_ex_data_t *ex_data = NULL;
    CK_RV ret = CKR_OK;
    ICA_EC_KEY *eckey;
    unsigned int privlen;
    int rc;

    UNUSED(sess);

    if (!ica_data->ica_ec_support_available) {
        TRACE_ERROR("ECC support is not available in Libica\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(ica_ex_data_t),
                             ica_need_wr_lock_ec_key, ica_free_ex_data);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->eckey == NULL) {
        /* Get the public key */
        ret = ica_build_ec_pub_key(key_obj, &ex_data->eckey,
                                   &ex_data->ec_privlen);
        if (ret != CKR_OK) {
            TRACE_ERROR("ica_build_ec_pub_key() failed with rc = 0x%lx. \n",
                        ret);
            goto end;
        }
    }

    eckey = ex_data->eckey;
    privlen = ex_data->ec_privlen;

    /* Signature length ok? */
    if (signature_len != 2 * privlen) {
        TRACE_ERROR("Supplied signature length mismatch: "
                    "supplied length = %ld, length from libica = %i\n",
                    signature_len, 2 * privlen);
        ret = CKR_SIGNATURE_LEN_RANGE;
        goto end;
    }

    /* Verify signature */
    rc = p_ica_ecdsa_verify(ica_data->adapter_handle,
                            eckey,
                            (unsigned char *) in_data,
                            (unsigned int) in_data_len,
                            (unsigned char *) signature, signature_len);
    switch (rc) {
    case 0:
        ret = CKR_OK;
        break;
    case ENODEV:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
        ret = CKR_FUNCTION_NOT_SUPPORTED;
        break;
    case EFAULT:
        TRACE_ERROR("ica_ecdsa_verify() returned invalid signature, "
                    "rc = %d. \n", rc);
        ret = CKR_SIGNATURE_INVALID;
        break;
    default:
        TRACE_ERROR("ica_ecdsa_verify() returned internal error, "
                    "rc = %d. \n", rc);
        ret = CKR_FUNCTION_FAILED;
        break;
    }

end:
    object_ex_data_unlock(key_obj);

    return ret;
}

CK_RV token_specific_ec_verify(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *signature,
                               CK_ULONG signature_len, OBJECT *key_obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_ec_signverify_available) {
        rc = ica_specific_ec_verify(tokdata, sess, in_data, in_data_len,
                                    signature, signature_len, key_obj);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_signverify_available = FALSE;
    }

    if (!ica_data->ica_ec_signverify_available)
        rc = openssl_specific_ec_verify(tokdata, sess, in_data, in_data_len,
                                        signature, signature_len, key_obj);

    return rc;
}

static CK_RV ica_prepare_ec_edwards_montgomery_ctx(OBJECT *key_obj,
                                                   void **ed_x_ctx,
                                                   int *nid)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr;
    int rc;

    /* Get CKA_EC_PARAMS from template */
    ret = template_attribute_get_non_empty(key_obj->template, CKA_EC_PARAMS,
                                           &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Determine curve nid */
    *nid = nid_from_oid(attr->pValue, attr->ulValueLen);
    if (*nid < 0) {
        TRACE_ERROR("Cannot determine curve nid. \n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    switch (*nid) {
    case NID_ED25519:
    case NID_ED448:
    case NID_X25519:
    case NID_X448:
        break;
    default:
        TRACE_ERROR("Must be an Edwards or Montgomery curve.\n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    /* Create Ed/X context object */
    rc = ica_ed_x_ctx_new(*nid, ed_x_ctx);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_ctx_new() failed for curve %i.\n", *nid);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV ica_build_ec_edwards_montgomery_priv_ctx(OBJECT *key_obj,
                                                      void **ed_x_ctx,
                                                      int *nid)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr;
    int rc;

    /* Prepare the ICA context */
    ret = ica_prepare_ec_edwards_montgomery_ctx(key_obj, ed_x_ctx, nid);
    if (ret != CKR_OK) {
        TRACE_ERROR("ica_prepare_ec_edwards_montgomery_ctx() failed with "
                    "rc = 0x%lx. \n", ret);
        return ret;
    }

    /* Get private key from template via CKA_VALUE */
    ret = template_attribute_get_non_empty(key_obj->template, CKA_VALUE,
                                           &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        ret = CKR_TEMPLATE_INCOMPLETE;
        goto end;
    }

    /* Initialize Ed/X with private key (D) */
    rc = ica_ed_x_key_set(*nid, *ed_x_ctx, attr->pValue, NULL,
                          attr->ulValueLen);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_key_set() failed with rc = %d \n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

end:
    if (ret != CKR_OK) {
        ica_ed_x_ctx_del(*nid, ed_x_ctx);
        *ed_x_ctx = NULL;
        *nid = NID_undef;
    }

    return ret;
}

static CK_RV ica_build_ec_edwards_montgomery_pub_ctx(OBJECT *key_obj,
                                                     void **ed_x_ctx,
                                                     int *nid)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE *attr;
    int rc;

    /* Prepare the ICA context */
    ret = ica_prepare_ec_edwards_montgomery_ctx(key_obj, ed_x_ctx, nid);
    if (ret != CKR_OK) {
        TRACE_ERROR("ica_prepare_ec_edwards_montgomery_ctx() failed with "
                    "rc = 0x%lx. \n", ret);
        return ret;
    }

    /* Get public key from template via CKA_EC_POINT */
    ret = template_attribute_get_non_empty(key_obj->template, CKA_EC_POINT,
                                           &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        ret = CKR_TEMPLATE_INCOMPLETE;
        goto end;
    }

    /* Initialize Ed/X with public key (X, Y) */
    rc = ica_ed_x_key_set(*nid, *ed_x_ctx, NULL, attr->pValue,
                          attr->ulValueLen);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_key_set() failed with rc = %d \n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

end:
    if (ret != CKR_OK) {
        ica_ed_x_ctx_del(*nid, ed_x_ctx);
        *ed_x_ctx = NULL;
        *nid = NID_undef;
    }

    return ret;
}

static CK_RV ica_check_ec_edwards_mech_param(OBJECT *key_obj,
                                             CK_MECHANISM *mech)
{
    CK_EDDSA_PARAMS* eddsa_params = NULL;
    CK_ATTRIBUTE *attr;
    CK_RV ret;
    int nid;

    if (mech->ulParameterLen == sizeof(CK_EDDSA_PARAMS) &&
         mech->pParameter != NULL) {
        eddsa_params = mech->pParameter;

        if (eddsa_params->ulContextDataLen != 0 ||
            eddsa_params->pContextData != NULL) {
            TRACE_ERROR("ICA does not support a non-empty context\n");
            return CKR_MECHANISM_PARAM_INVALID;
        }

        if (eddsa_params->phFlag) {
            TRACE_ERROR("ICA does not support pre-hash\n");
            return CKR_MECHANISM_PARAM_INVALID;
        }
    }

    /* Get CKA_EC_PARAMS from template */
    ret = template_attribute_get_non_empty(key_obj->template, CKA_EC_PARAMS,
                                           &attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Determine curve nid */
    nid = nid_from_oid(attr->pValue, attr->ulValueLen);
    if (nid < 0) {
        TRACE_ERROR("Cannot determine curve nid. \n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    switch (nid) {
    case NID_ED25519:
        break;
    case NID_ED448:
        if (eddsa_params == NULL) {
            TRACE_ERROR("Mechanism parameter is required for Ed448\n");
            return CKR_MECHANISM_PARAM_INVALID;
        }
        break;
    default:
        TRACE_ERROR("Not an edwards curve.\n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    return CKR_OK;
}

static CK_RV ica_specific_ec_edwards_sign(STDLL_TokData_t *tokdata,
                                          SESSION *sess, CK_BYTE *in_data,
                                          CK_ULONG in_data_len,
                                          CK_BYTE *out_data,
                                          CK_ULONG *out_data_len,
                                          OBJECT *key_obj,
                                          CK_MECHANISM *mech)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    ica_ex_data_t *ex_data = NULL;
    CK_RV ret = CKR_OK;
    int rc;

    UNUSED(sess);
    UNUSED(mech);

    if (!ica_data->ica_ec_edwards_support_available) {
        TRACE_ERROR("EC-Edwards support is not available in Libica\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(ica_ex_data_t),
                             ica_need_wr_lock_ec_key, ica_free_ex_data);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->ed_x_ctx == NULL) {
        /* Get the private key */
        ret = ica_build_ec_edwards_montgomery_priv_ctx(key_obj,
                                                       &ex_data->ed_x_ctx,
                                                       &ex_data->ed_x_nid);
        if (ret != CKR_OK) {
            TRACE_ERROR("ica_build_ec_edwards_montgomery_priv_ctx() failed "
                        "with rc = 0x%lx. \n", ret);
            goto end;
        }
    }

    /* Create signature */
    rc = ica_eddsa_sign(ex_data->ed_x_nid, ex_data->ed_x_ctx,
                        out_data, out_data_len, in_data, in_data_len);
    if (rc != 0) {
        switch (rc) {
        case ENODEV:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
        default:
            TRACE_ERROR("ica_eddsa_sign() failed with rc = %d. \n", rc);
            ret = CKR_FUNCTION_FAILED;
            break;
        }
        goto end;
    }

    ret = CKR_OK;

end:
    object_ex_data_unlock(key_obj);

    return ret;
}

CK_RV token_specific_ec_edwards_sign(STDLL_TokData_t *tokdata,  SESSION *sess,
                                     CK_BYTE *in_data, CK_ULONG in_data_len,
                                     CK_BYTE *out_data, CK_ULONG *out_data_len,
                                     OBJECT *key_obj, CK_MECHANISM *mech)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;

    rc = ica_check_ec_edwards_mech_param(key_obj, mech);
    if (rc != CKR_OK)
        return rc;

    if (ica_data->ica_ec_edwards_signverify_available) {
        rc = ica_specific_ec_edwards_sign(tokdata, sess, in_data, in_data_len,
                                          out_data, out_data_len, key_obj,
                                          mech);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_edwards_signverify_available = FALSE;
    }

    if (!ica_data->ica_ec_edwards_signverify_available)
        rc = openssl_specific_ec_edwards_sign(tokdata, sess,
                                              in_data, in_data_len,
                                              out_data, out_data_len,
                                              key_obj, mech);

    return rc;
}

static CK_RV ica_specific_ec_edwards_verify(STDLL_TokData_t *tokdata,
                                            SESSION *sess, CK_BYTE *in_data,
                                            CK_ULONG in_data_len,
                                            CK_BYTE *signature,
                                            CK_ULONG signature_len,
                                            OBJECT *key_obj,
                                            CK_MECHANISM *mech)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    ica_ex_data_t *ex_data = NULL;
    CK_RV ret = CKR_OK;
    int rc;

    UNUSED(sess);
    UNUSED(mech);

    if (!ica_data->ica_ec_support_available) {
        TRACE_ERROR("ECC support is not available in Libica\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(ica_ex_data_t),
                             ica_need_wr_lock_ec_key, ica_free_ex_data);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->ed_x_ctx == NULL) {
        /* Get the public key */
        ret = ica_build_ec_edwards_montgomery_pub_ctx(key_obj,
                                                      &ex_data->ed_x_ctx,
                                                      &ex_data->ed_x_nid);
        if (ret != CKR_OK) {
            TRACE_ERROR("ica_build_ec_edwards_montgomery_pub_ctx() failed with "
                        "rc = 0x%lx. \n", ret);
            goto end;
        }
    }

    /* Verify signature */
    rc = ica_eddsa_verify(ex_data->ed_x_nid, ex_data->ed_x_ctx,
                          signature, signature_len, in_data, in_data_len);
    switch (rc) {
    case 0:
        ret = CKR_OK;
        break;
    case ENODEV:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
        ret = CKR_FUNCTION_NOT_SUPPORTED;
        break;
    default:
        TRACE_ERROR("ica_eddsa_verify() returned invalid signature, "
                    "rc = %d. \n", rc);
        ret = CKR_SIGNATURE_INVALID;
        break;
    }

end:
    object_ex_data_unlock(key_obj);

    return ret;
}

CK_RV token_specific_ec_edwards_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                       CK_BYTE *in_data, CK_ULONG in_data_len,
                                       CK_BYTE *signature,
                                       CK_ULONG signature_len, OBJECT *key_obj,
                                       CK_MECHANISM *mech)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc;

    rc = ica_check_ec_edwards_mech_param(key_obj, mech);
    if (rc != CKR_OK)
        return rc;

    if (ica_data->ica_ec_edwards_signverify_available) {
        rc = ica_specific_ec_edwards_verify(tokdata, sess, in_data, in_data_len,
                                            signature, signature_len, key_obj,
                                            mech);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_edwards_signverify_available = FALSE;
    }

    if (!ica_data->ica_ec_edwards_signverify_available)
        rc = openssl_specific_ec_edwards_verify(tokdata, sess,
                                                in_data, in_data_len,
                                                signature, signature_len,
                                                key_obj, mech);

    return rc;
}

static CK_RV ica_specific_montgomery_ecdh_pkcs_derive(STDLL_TokData_t *tokdata,
                                                      CK_BYTE *priv_bytes,
                                                      CK_ULONG priv_length,
                                                      CK_BYTE *pub_bytes,
                                                      CK_ULONG pub_length,
                                                      CK_BYTE *secret_value,
                                                      CK_ULONG *secret_value_len,
                                                      int nid)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV ret = CKR_OK;
    void *ctx = NULL;
    int rc;

    UNUSED(tokdata);

    *secret_value_len = 0;

    if (!ica_data->ica_ec_montgomery_support_available) {
        TRACE_ERROR("EC-Montgomery support is not available in Libica\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    /* Create ICA object with private key */
    rc = ica_ed_x_ctx_new(nid, &ctx);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_ctx_new() failed for curve %i.\n", nid);
        return CKR_FUNCTION_FAILED;
    }

    rc = ica_ed_x_key_set(nid, ctx, priv_bytes, NULL, priv_length);
    if (rc != 0) {
        TRACE_ERROR("ica_ed_x_key_set() failed with rc = %d \n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    /* Calculate shared secret z */
    rc = ica_x_derive(nid, ctx, secret_value, pub_bytes, pub_length);
    if (rc != 0) {
        switch (rc) {
        case ENODEV:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
        case EPERM:
            TRACE_ERROR("ica_x_derive() failed with rc=EPERM, probably curve "
                        "not supported by openssl.\n");
            ret = CKR_CURVE_NOT_SUPPORTED;
            break;
        default:
            TRACE_ERROR("ica_x_derive() failed with rc = %d. \n", rc);
            ret = CKR_FUNCTION_FAILED;
            break;
        }
        goto end;
    }

    *secret_value_len = priv_length;
    ret = CKR_OK;

end:
    ica_ed_x_ctx_del(nid, &ctx);

    return ret;
}


static CK_RV ica_specific_ecdh_pkcs_derive(STDLL_TokData_t *tokdata,
                                           CK_BYTE *priv_bytes,
                                           CK_ULONG priv_length,
                                           CK_BYTE *pub_bytes,
                                           CK_ULONG pub_length,
                                           CK_BYTE *secret_value,
                                           CK_ULONG *secret_value_len,
                                           CK_BYTE *oid, CK_ULONG oid_length)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV ret = CKR_OK;
    ICA_EC_KEY *pubkey = NULL, *privkey = NULL;
    unsigned int n, privlen, i;
    unsigned char d_array[ICATOK_EC_MAX_D_LEN];
    unsigned char x_array[ICATOK_EC_MAX_D_LEN];
    unsigned char y_array[ICATOK_EC_MAX_D_LEN];
    int rc, nid;
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len;
    CK_BBOOL allocated = FALSE;

    /* Get nid from oid */
    nid = nid_from_oid(oid, oid_length);
    if (nid < 0) {
        TRACE_ERROR("curve not supported by icatoken.\n");
        return CKR_CURVE_NOT_SUPPORTED;
    }

    switch (nid) {
    case NID_X25519:
    case NID_X448:
        return ica_specific_montgomery_ecdh_pkcs_derive(tokdata, priv_bytes,
                                                        priv_length, pub_bytes,
                                                        pub_length,
                                                        secret_value,
                                                        secret_value_len,
                                                        nid);
    case NID_ED25519:
    case NID_ED448:
        return CKR_CURVE_NOT_SUPPORTED;
    default:
        break;
    }

    *secret_value_len = 0;

    if (!ica_data->ica_ec_support_available) {
        TRACE_ERROR("ECC support is not available in Libica\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    /* Create ICA_EC_KEY object with public key */
    pubkey = p_ica_ec_key_new(nid, &privlen);
    if (!pubkey) {
        TRACE_ERROR("ica_ec_key_new() for curve %i failed.\n", nid);
        return CKR_FUNCTION_FAILED;
    }

    ret = ec_point_from_public_data(pub_bytes, pub_length, privlen, TRUE,
                                   &allocated, &ecpoint, &ecpoint_len);
    if (ret != CKR_OK) {
        TRACE_DEVEL("ec_point_from_public_data failed\n");
        goto end;
    }

    /* Provide (X,Y), decompress key if necessary */
    ret = set_pubkey_coordinates(nid, ecpoint, ecpoint_len,
                                 privlen, x_array, y_array);
    if (ret != 0) {
        TRACE_ERROR("Cannot determine public key coordinates\n");
        goto end;
    }

    /* Format (D) as char array with leading nulls if necessary */
    n = privlen - priv_length;
    for (i = 0; i < n; i++)
        d_array[i] = 0x00;
    memcpy(&(d_array[n]), priv_bytes, priv_length);

    /* Initialize ICA_EC_KEY with public key (X,Y) */
    rc = p_ica_ec_key_init(x_array, y_array, NULL, pubkey);
    if (rc != 0) {
        TRACE_ERROR("ica_ec_key_init() for public key failed with "
                    "rc = %d \n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    /* Create ICA_EC_KEY object with private key */
    privkey = p_ica_ec_key_new(nid, &privlen);
    if (!privkey) {
        TRACE_ERROR("ica_ec_key_new() for curve %i failed. \n", nid);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    /* Initialize ICA_EC_KEY with private key (D) */
    rc = p_ica_ec_key_init(NULL, NULL, d_array, privkey);
    if (rc != 0) {
        TRACE_ERROR("ica_ec_key_init() for private key failed with "
                    "rc = %d \n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto end;
    }

    /* Calculate shared secret z */
    rc = p_ica_ecdh_derive_secret(ica_data->adapter_handle, privkey,
                                  pubkey, secret_value, privlen);
    if (rc != 0) {
        switch (rc) {
        case ENODEV:
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
            ret = CKR_FUNCTION_NOT_SUPPORTED;
            break;
        case EPERM:
            TRACE_ERROR("ica_ecdh_derive_secret() failed with rc=EPERM, probably curve not supported by openssl.\n");
            ret = CKR_CURVE_NOT_SUPPORTED;
            break;
        default:
            TRACE_ERROR("ica_ecdh_derive_secret() failed with rc = %d. \n", rc);
            ret = CKR_FUNCTION_FAILED;
            break;
        }
        goto end;
    }

    *secret_value_len = privlen;
    ret = CKR_OK;

end:
    if (allocated && ecpoint != NULL)
        free(ecpoint);
    p_ica_ec_key_free(privkey);
    p_ica_ec_key_free(pubkey);

    return ret;
}

CK_RV token_specific_ecdh_pkcs_derive(STDLL_TokData_t *tokdata,
                                      CK_BYTE *priv_bytes,
                                      CK_ULONG priv_length,
                                      CK_BYTE *pub_bytes,
                                      CK_ULONG pub_length,
                                      CK_BYTE *secret_value,
                                      CK_ULONG *secret_value_len,
                                      CK_BYTE *oid, CK_ULONG oid_length)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;

    if (ica_data->ica_ec_derive_available) {
        rc = ica_specific_ecdh_pkcs_derive(tokdata, priv_bytes, priv_length,
                                           pub_bytes, pub_length,
                                           secret_value, secret_value_len,
                                           oid, oid_length);
        if (rc == CKR_FUNCTION_NOT_SUPPORTED)
            ica_data->ica_ec_derive_available = FALSE;
    }

    if (!ica_data->ica_ec_derive_available)
        rc = openssl_specific_ecdh_pkcs_derive(tokdata, priv_bytes, priv_length,
                                               pub_bytes, pub_length,
                                               secret_value, secret_value_len,
                                               oid, oid_length);

    return rc;
}

#endif

CK_RV token_specific_object_add(STDLL_TokData_t *tokdata, SESSION *sess,
                                OBJECT *obj)
{
    ica_private_data_t *ica_data = (ica_private_data_t *)tokdata->private_data;
    CK_ATTRIBUTE *value = NULL;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE keytype;
#ifndef NO_EC
    ICA_EC_KEY *ica_eckey = NULL;
    unsigned int privlen;
    void *ctx = NULL;
    int nid = NID_undef;
    EVP_PKEY *ossl_eckey = NULL;
#endif
    CK_RV rc;

    UNUSED(sess);
#ifdef NO_EC
    UNUSED(ica_data);
#endif

    rc = template_attribute_get_ulong(obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK)
        return CKR_OK;

    rc = template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK)
        return CKR_OK;

    switch (keytype) {
#ifndef NO_EC
    case CKK_EC:
        if (ica_data->ica_ec_keygen_available) {
            /* Check if libica supports the curve */
            switch (class) {
            case CKO_PRIVATE_KEY:
                rc = ica_build_ec_priv_key(obj, &ica_eckey, &privlen);
                if (ica_eckey != NULL)
                    p_ica_ec_key_free(ica_eckey);
                return rc;
            case CKO_PUBLIC_KEY:
                rc = ica_build_ec_pub_key(obj, &ica_eckey, &privlen);
                if (ica_eckey != NULL)
                    p_ica_ec_key_free(ica_eckey);
                return rc;
            default:
                return CKR_KEY_TYPE_INCONSISTENT;
            }
        } else {
            /* Check if OpenSSL supports the curve */
            rc = openssl_make_ec_key_from_template(obj->template, &ossl_eckey);
            if (ossl_eckey != NULL)
                    EVP_PKEY_free(ossl_eckey);
            return rc;
        }
        return CKR_OK;
    case CKK_EC_EDWARDS:
    case CKK_EC_MONTGOMERY:
        if ((keytype == CKK_EC_EDWARDS &&
             ica_data->ica_ec_edwards_keygen_available) ||
            (keytype == CKK_EC_MONTGOMERY &&
             ica_data->ica_ec_montgomery_keygen_available)) {
            /* Check if libica supports Edwards/Montgomery */
            switch (class) {
            case CKO_PRIVATE_KEY:
                rc = ica_build_ec_edwards_montgomery_priv_ctx(obj, &ctx, &nid);
                if (ctx != NULL)
                    ica_ed_x_ctx_del(nid, &ctx);
                if (rc != CKR_OK)
                    return rc;
                break;
            case CKO_PUBLIC_KEY:
                rc = ica_build_ec_edwards_montgomery_pub_ctx(obj, &ctx, &nid);
                if (ctx != NULL)
                    ica_ed_x_ctx_del(nid, &ctx);
                if (rc != CKR_OK)
                    return rc;
                break;
            default:
                return CKR_KEY_TYPE_INCONSISTENT;
            }

            switch (nid) {
            case NID_ED25519:
            case NID_ED448:
                if (keytype != CKK_EC_EDWARDS) {
                    TRACE_ERROR("Edwards curve only supported with "
                                "CKK_EC_EDWARDS key type.\n");
                    return CKR_CURVE_NOT_SUPPORTED;
                }
                break;
            case NID_X25519:
            case NID_X448:
                if (keytype != CKK_EC_MONTGOMERY) {
                    TRACE_ERROR("Montgomery curve only supported with "
                                "CKK_EC_MONTGOMERY key type.\n");
                    return CKR_CURVE_NOT_SUPPORTED;
                }
                break;
            default:
                return CKR_CURVE_NOT_SUPPORTED;
            }
        } else {
            /* Check if OpenSSL supports the curve */
            rc = openssl_make_ec_key_from_template(obj->template, &ossl_eckey);
            if (ossl_eckey != NULL)
                    EVP_PKEY_free(ossl_eckey);
            return rc;
        }
        return CKR_OK;
#endif

    case CKK_AES_XTS:
        rc = template_attribute_get_non_empty(obj->template, CKA_VALUE, &value);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to get CKA_VALUE\n");
            return rc;
        }

        if (memcmp(value->pValue,
                   ((CK_BYTE *)value->pValue) + value->ulValueLen / 2,
                   value->ulValueLen / 2) == 0) {
            TRACE_ERROR("The 2 key parts of an AES-XTS key can not be the same\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return CKR_OK;

    default:
        return CKR_OK;
    }
}

CK_RV token_specific_get_token_info(STDLL_TokData_t *tokdata,
                                    CK_TOKEN_INFO_PTR pInfo)
{
    libica_version_info ver;
    int rc;

    UNUSED(tokdata);

    rc = ica_get_version(&ver);
    if (rc != 0) {
        TRACE_ERROR("ica_get_version failed with %i\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    pInfo->firmwareVersion.major = ver.major_version;
    pInfo->firmwareVersion.minor = ver.minor_version;
    pInfo->hardwareVersion.major = pInfo->firmwareVersion.major;
    pInfo->hardwareVersion.minor = pInfo->firmwareVersion.minor;

    return CKR_OK;
}
