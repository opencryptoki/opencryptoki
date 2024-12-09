/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * openCryptoki CCA token
 *
 * Author: Kent E. Yoder <yoder1@us.ibm.com>
 *
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>
#include <syslog.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <errno.h>
#include <regex.h>
#include <dirent.h>
#ifndef NO_PKEY
#include <sys/ioctl.h>
#include <unistd.h>
#include <asm/pkey.h>
#endif
#include "platform.h"
#include "cca_stdll.h"
#include "p11util.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "h_extern.h"
#include "ec_defs.h"
#include "trace.h"
#include "ock_syslog.h"
#include "cfgparser.h"
#include "events.h"
#include "constant_time.h"
#include "pqc_defs.h"
#include <openssl/crypto.h>
#include <openssl/ec.h>
#ifndef NO_PKEY
#include "pkey_utils.h"
#endif
#include "attributes.h"

/**
 * EC definitions
 */

/**
 * the point is encoded as z||x, where the octet z specifies
 * which solution of the quadratic equation y is
 */
#define POINT_CONVERSION_COMPRESSED      0x02

/**
 * the point is encoded as z||x||y, where z is the octet 0x04
 */
#define POINT_CONVERSION_UNCOMPRESSED    0x04

/**
 * the point is encoded as z||x||y, where the octet z specifies
 * which solution of the quadratic equation y is
 */
#define POINT_CONVERSION_HYBRID          0x06


const char manuf[] = "IBM";
const char model[] = "CCA";
const char descr[] = "IBM CCA Token";
const char label[] = "ccatok";

#if defined(_AIX)
    /* GNU extension, provides a replacement */
    void populate_progname(void);
    extern char *program_invocation_short_name;

    #if defined(__64BIT__) /* -q64 was passed */
         #define CCASHAREDLIB "libcsufcca.a(sapi64)"
    #else
         #define CCASHAREDLIB "libcsufcca.a(sapi)"
    #endif /* __64BIT__ */
#else
#define CCASHAREDLIB "libcsulcca.so"
#endif

#define CCA_MIN_VERSION     7
#define CCA_MIN_RELEASE     1

static CSNBCKI_t dll_CSNBCKI;
static CSNBCKM_t dll_CSNBCKM;
static CSNBDKX_t dll_CSNBDKX;
static CSNBDKM_t dll_CSNBDKM;
static CSNBKEX_t dll_CSNBKEX;
static CSNBKGN_t dll_CSNBKGN;
static CSNBKGN2_t dll_CSNBKGN2;
static CSNBKIM_t dll_CSNBKIM;
static CSNBKPI_t dll_CSNBKPI;
static CSNBKPI2_t dll_CSNBKPI2;
static CSNBKSI_t dll_CSNBKSI;
static CSNBKRC_t dll_CSNBKRC;
static CSNBAKRC_t dll_CSNBAKRC;
static CSNBKRD_t dll_CSNBKRD;
static CSNBKRL_t dll_CSNBKRL;
static CSNBKRR_t dll_CSNBKRR;
static CSNBKRW_t dll_CSNBKRW;
static CSNDKRC_t dll_CSNDKRC;
static CSNDKRD_t dll_CSNDKRD;
static CSNDKRL_t dll_CSNDKRL;
static CSNDKRR_t dll_CSNDKRR;
static CSNDKRW_t dll_CSNDKRW;
static CSNBKYT_t dll_CSNBKYT;
static CSNBKYTX_t dll_CSNBKYTX;
CSNBKTC_t dll_CSNBKTC;
CSNBKTC2_t dll_CSNBKTC2;
static CSNBKTR_t dll_CSNBKTR;
static CSNBRNG_t dll_CSNBRNG;
static CSNBRNGL_t dll_CSNBRNGL;
static CSNBSAE_t dll_CSNBSAE;
static CSNBSAD_t dll_CSNBSAD;
static CSNBDEC_t dll_CSNBDEC;
static CSNBENC_t dll_CSNBENC;
static CSNBMGN_t dll_CSNBMGN;
static CSNBMVR_t dll_CSNBMVR;
static CSNBKTB_t dll_CSNBKTB;
static CSNBKTB2_t dll_CSNBKTB2;
static CSNDPKG_t dll_CSNDPKG;
static CSNDPKB_t dll_CSNDPKB;
static CSNBOWH_t dll_CSNBOWH;
static CSNDPKI_t dll_CSNDPKI;
static CSNDDSG_t dll_CSNDDSG;
static CSNDDSV_t dll_CSNDDSV;
CSNDKTC_t dll_CSNDKTC;
static CSNDPKX_t dll_CSNDPKX;
static CSNDSYI_t dll_CSNDSYI;
static CSNDSYI2_t dll_CSNDSYI2;
static CSNDSYX_t dll_CSNDSYX;
static CSUACFQ_t dll_CSUACFQ;
static CSUACFC_t dll_CSUACFC;
static CSNDSBC_t dll_CSNDSBC;
static CSNDSBD_t dll_CSNDSBD;
static CSUALCT_t dll_CSUALCT;
static CSUAACM_t dll_CSUAACM;
static CSUAACI_t dll_CSUAACI;
static CSNDPKH_t dll_CSNDPKH;
static CSNDPKR_t dll_CSNDPKR;
static CSUAMKD_t dll_CSUAMKD;
static CSNDRKD_t dll_CSNDRKD;
static CSNDRKL_t dll_CSNDRKL;
static CSNDSYG_t dll_CSNDSYG;
static CSNBPTR_t dll_CSNBPTR;
static CSNBCPE_t dll_CSNBCPE;
static CSNBCPA_t dll_CSNBCPA;
static CSNBPGN_t dll_CSNBPGN;
static CSNBPVR_t dll_CSNBPVR;
static CSNBDKG_t dll_CSNBDKG;
static CSNBEPG_t dll_CSNBEPG;
static CSNBCVE_t dll_CSNBCVE;
static CSNBCSG_t dll_CSNBCSG;
static CSNBCSV_t dll_CSNBCSV;
static CSNBCVG_t dll_CSNBCVG;
static CSNBKTP_t dll_CSNBKTP;
static CSNDPKE_t dll_CSNDPKE;
static CSNDPKD_t dll_CSNDPKD;
static CSNBPEX_t dll_CSNBPEX;
static CSNBPEXX_t dll_CSNBPEXX;
static CSUARNT_t dll_CSUARNT;
static CSNBCVT_t dll_CSNBCVT;
static CSNBMDG_t dll_CSNBMDG;
CSUACRA_t dll_CSUACRA;
CSUACRD_t dll_CSUACRD;
static CSNBTRV_t dll_CSNBTRV;
static CSNBSKY_t dll_CSNBSKY;
static CSNBSPN_t dll_CSNBSPN;
static CSNBPCU_t dll_CSNBPCU;
static CSUAPRB_t dll_CSUAPRB;
static CSNDTBC_t dll_CSNDTBC;
static CSNDRKX_t dll_CSNDRKX;
static CSNBKET_t dll_CSNBKET;
static CSNBHMG_t dll_CSNBHMG;
static CSNBHMV_t dll_CSNBHMV;
static CSNBCTT2_t dll_CSNBCTT2;
static CSUACFV_t dll_CSUACFV;
static CSNBRKA_t dll_CSNBRKA;
static CSNBKTR2_t dll_CSNBKTR2;
static CSNDEDH_t dll_CSNDEDH;

/*
 * The CCA adapter lock is shared between all CCA token instances within the
 * same process. Users of the CCA adapter(s) should obtain a READ lock, to
 * be sure that no CCA adapter and/or domain selection is done concurrently.
 * Whenever a CCA adapter and/or domain selection is performed, a WRITE lock
 * must be obtained. This blocks all users until the selection processing is
 * finished.
 * While CCA device selection has thread scope, domain selection seems to have
 * process scope. Thus, domain selection influences not only the current thread,
 * but all threads of the process.
 */
pthread_rwlock_t cca_adapter_rwlock;
static unsigned long cca_adapter_rwlock_ref_count = 0;

/* mechanisms provided by this token */
static const MECH_LIST_ELEMENT cca_mech_list[] = {
    {CKM_DES_KEY_GEN, {8, 8, CKF_HW | CKF_GENERATE}},
    {CKM_DES3_KEY_GEN, {24, 24, CKF_HW | CKF_GENERATE}},
    {CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 4096, CKF_HW | CKF_GENERATE_KEY_PAIR}},
    {CKM_RSA_PKCS, {512, 4096, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN |
                    CKF_VERIFY | CKF_WRAP | CKF_UNWRAP}},
    {CKM_MD5_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA3_224_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA3_256_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA3_384_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA3_512_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_RSA_PKCS_PSS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS_PSS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_RSA_PKCS_PSS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS_PSS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS_PSS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS_PSS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_RSA_PKCS_OAEP, {512, 4096, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT |
                                                  CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC,
     {8, 8, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES_CBC_PAD,
     {8, 8, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES3_CBC,
     {24, 24, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES3_CBC_PAD,
     {24, 24, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_KEY_GEN, {16, 32, CKF_HW | CKF_GENERATE}},
    {CKM_AES_XTS_KEY_GEN, {32, 64, CKF_HW | CKF_GENERATE}},
    {CKM_AES_ECB, {16, 32, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_CBC, {16, 32, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_CBC_PAD, {16, 32, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_XTS, {32, 64, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_SHA3_512, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA3_384, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA3_256, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA3_224, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_IBM_SHA3_512, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_IBM_SHA3_384, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_IBM_SHA3_256, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_IBM_SHA3_224, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA512, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA512_HMAC, {256, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_HMAC_GENERAL, {256, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA384_HMAC, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_HMAC_GENERAL, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_HMAC_GENERAL, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA224_HMAC, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_HMAC_GENERAL, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA_1, {0, 0, CKF_DIGEST}},
    {CKM_SHA_1_HMAC, {80, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA_1_HMAC_GENERAL, {80, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_MD5, {0, 0, CKF_DIGEST}},
    {CKM_EC_KEY_PAIR_GEN, {160, 521, CKF_HW | CKF_GENERATE_KEY_PAIR |
                           CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE |
                 CKF_EC_F_P}},
    {CKM_ECDSA_SHA1, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                      CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA224, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA256, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA384, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA512, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA3_224, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA3_256, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA3_384, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA_SHA3_512, {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY |
                        CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDH1_DERIVE, {160, 521, CKF_DERIVE | CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_HW | CKF_GENERATE}},
    {CKM_IBM_DILITHIUM, {256, 256, CKF_HW | CKF_GENERATE_KEY_PAIR |
                         CKF_SIGN | CKF_VERIFY}},
    {CKM_RSA_AES_KEY_WRAP, {2048, 4096, CKF_HW | CKF_WRAP | CKF_UNWRAP}},
};

static const CK_ULONG cca_mech_list_len =
                        (sizeof(cca_mech_list) / sizeof(MECH_LIST_ELEMENT));

const unsigned char cca_zero_mkvp[CCA_MKVP_LENGTH] = { 0 };

static CK_RV file_fgets(const char *fname, char *buf, size_t buflen);

static CK_RV cca_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                         enum cca_key_type type, CK_BYTE *key,
                         unsigned char *key_form, unsigned char *key_type_1,
                         CK_ULONG key_size, CK_BBOOL aes_xts_2dn_key,
                         CK_BBOOL *has_new_mk);

static CK_RV cca_cipher_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                enum cca_key_type type,
                                CK_BYTE *key, CK_ULONG *key_len,
                                unsigned char *key_form,
                                unsigned char *key_type_1,
                                CK_ULONG key_size, CK_BBOOL aes_xts_2dn_key,
                                CK_BBOOL *has_new_mk);
static CK_RV cca_build_aes_cipher_token(STDLL_TokData_t *tokdata,
                                        TEMPLATE *tmpl, CK_BYTE *key_token,
                                        CK_ULONG *key_token_size);
static CK_RV cca_build_aes_data_token(STDLL_TokData_t *tokdata,
                                      CK_ULONG key_size,
                                      CK_BYTE *key_token,
                                      CK_ULONG *key_token_size);
static CK_RV cca_aes_cipher_add_key_usage_keywords(STDLL_TokData_t *tokdata,
                                                   TEMPLATE *tmpl,
                                                   CK_BYTE *rule_array,
                                                   CK_ULONG rule_array_size,
                                                   CK_ULONG *rule_array_count);

static CK_RV init_cca_adapter_lock(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    pthread_rwlockattr_t attr;
    unsigned long cnt;

    /*
     * Only for DOM-ANY, we will perform domain selections. Thus, we only need
     * to use the CCA adapter lock for for DOM-ANY configurations.
     */
    if (!cca_private->dom_any)
        return CKR_OK;

    cnt = __sync_add_and_fetch(&cca_adapter_rwlock_ref_count, 1);
    if (cnt > 1)
        return CKR_OK;

#if !defined(_AIX)
    if (pthread_rwlockattr_init(&attr) != 0) {
        TRACE_ERROR("pthread_rwlockattr_init failed\n");
        OCK_SYSLOG(LOG_ERR, "%s: Failed to initialize the CCA adapter lock\n",
                   __func__);
        return CKR_CANT_LOCK;
    }

    if (pthread_rwlockattr_setkind_np(&attr,
                  PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) != 0) {
        TRACE_ERROR("pthread_rwlockattr_setkind_np failed\n");
        OCK_SYSLOG(LOG_ERR, "%s: Failed to initialize the CCA adapter lock\n",
                   __func__);
        pthread_rwlockattr_destroy(&attr);
        return CKR_CANT_LOCK;
    }
#endif

    if (pthread_rwlock_init(&cca_adapter_rwlock, &attr) != 0) {
        TRACE_ERROR("pthread_rwlock_init failed\n");
        OCK_SYSLOG(LOG_ERR, "%s: Failed to initialize the CCA adapter lock\n",
                   __func__);
        pthread_rwlockattr_destroy(&attr);
        return CKR_CANT_LOCK;
    }

    pthread_rwlockattr_destroy(&attr);

    return CKR_OK;
}

static void destroy_cca_adapter_lock(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned long cnt;

    /*
     * Only for DOM-ANY, we will perform domain selections. Thus, we only need
     * to use the CCA adapter lock for for DOM-ANY configurations.
     */
    if (!cca_private->dom_any)
        return;

    cnt = __sync_sub_and_fetch(&cca_adapter_rwlock_ref_count, 1);

    if (cnt == 0)
        pthread_rwlock_destroy(&cca_adapter_rwlock);
}

/*
 * Helper function: Analyse given CCA token.
 * returns TRUE and keytype, keybitsize, and MKVP address if token is known
 * and seems to be valid (only basic checks are done), otherwise FALSE.
 */
CK_BBOOL analyse_cca_key_token(const CK_BYTE *t, CK_ULONG tlen,
                               enum cca_token_type *keytype,
                               unsigned int *keybitsize,
                               const CK_BYTE **mkvp)
{
    if (t[0] == 0x01 && (t[4] == 0x00 || t[4] == 0x01)) {
        /* internal secure cca des data key with exact 64 bytes */
        if (tlen != 64) {
            TRACE_DEVEL("CCA DES token has invalid token size %lu != 64\n", tlen);
            return FALSE;
        }
        *keytype = sec_des_data_key;
        if (t[4] == 0x00) { /* version 0 */
            /* CV base is at offset 32, regardless of the type of key */
            uint64_t cv = *((uint64_t *)&(t[32]));
            /* make it endian-safe */
            cv = be64toh(cv);
            /* bits 40-42, but numbered starting from the MSB */
            uint64_t keyform_mask = 0xE00000;
            /* rshift keyform to a form that'll fit in a byte */
            uint8_t keyform = (cv & keyform_mask) >> 21;

            /*
             * refer to Figure 37 of LoZ CCA Programmer's Guide, v8 (2014)
             * also available online at https://www.ibm.com/docs/en/linux-on-systems?topic=table-control-vector-base-bit-maps#l0wskc02_cvbbmap__wskc_cv_base_bit_map_1_of_4
             */
            switch (keyform) {
                case 0: {
                    *keybitsize = 8 * 8;
                    break;
                }
                case 2:   /* DOUBLE */
                case 6: { /* DOUBLE-O */
                    *keybitsize = 2 * 8 * 8;
                    break;
                }
                case 3:   /* TRIPLE */
                case 7: { /* TRIPLE-O */
                    *keybitsize = 3 * 8 * 8;
                    break;
                }
                default: {
                    TRACE_DEVEL("CCA DES DATA CV keyform has invalid value (%02d) for version 0 format specifications.\n", keyform);
                    return FALSE;
                }
            }
        } else if (t[4] == 0x01) { /* version 1 */
            if (t[59] == 0x10)
                *keybitsize = 16 * 8;
            else if (t[59] == 0x20)
                *keybitsize = 24 * 8;
            else {
                TRACE_DEVEL("CCA DES data key token has invalid/unknown keysize 0x%02x for version 1 format specifications.\n", (int)t[59]);
                return FALSE;
            }
        }
        *mkvp = &t[8];
        return TRUE;
    }

    if (t[0] == 0x01 && t[4] == 0x04) {
        /* internal secure cca aes data key with exact 64 bytes */
        if (tlen != 64) {
            TRACE_DEVEL("CCA AES data key token has invalid token size %lu != 64\n", tlen);
            return FALSE;
        }
        *keytype = sec_aes_data_key;
        *keybitsize = be16toh(*((uint16_t *)(t + 56)));
        if (*keybitsize != 128 && *keybitsize != 192 && *keybitsize != 256) {
            TRACE_DEVEL("CCA AES data key token has invalid/unknown keybitsize %u\n", *keybitsize);
            return FALSE;
        }
        *mkvp = &t[8];
        return TRUE;
    }

    if (t[0] == 0x01 && t[4] == 0x05 && t[41] == 0x02) {
        /* internal variable length secure cca aes cipher key */
        uint16_t key_type = be16toh(*((uint16_t*)(t + 42)));
        if (key_type != 0x0001) {
            TRACE_DEVEL("CCA AES cipher key token has invalid/unknown keytype 0x%04hx\n", key_type);
            return FALSE;
        }
        *keytype = sec_aes_cipher_key;
        if (t[28] == 0x00) { /* V0 payload */
            switch (be16toh(*((uint16_t*)(t + 38)))) {
            case 512:
                *keybitsize = 128;
                break;
            case 576:
                *keybitsize = 192;
                break;
            case 640:
                *keybitsize = 256;
                break;
             default:
                 *keybitsize = 0; /* unknown */
                 break;
            }
        } else {
            *keybitsize = 0; /* no chance to find out the key bit size for V1 */
        }
        *mkvp = &t[10];
        return TRUE;
    }

    if (t[0] == 0x01 && t[4] == 0x05 && t[41] == 0x03) {
        /* internal variable length HMAC key */
        uint16_t key_type = be16toh(*((uint16_t*)(t + 42)));
        if (key_type != 0x0002) {
            TRACE_DEVEL("CCA HMAC key token has invalid/unknown keytype 0x%04hx\n", key_type);
            return FALSE;
        }
        if (t[8] != 0x03) {
            TRACE_DEVEL("CCA HMAC key token has unsupported format t[8]=%hhu != 0x03\n", t[8]);
            return FALSE;
        }
        if (t[26] != 0x02) {
            TRACE_DEVEL("CCA HMAC key token has unsupported format t[26]=%hhu != 0x02\n", t[26]);
            return FALSE;
        }
        if (t[27] != 0x02) {
            TRACE_DEVEL("CCA HMAC key token has unsupported format t[27]=%hhu != 0x02\n", t[26]);
            return FALSE;
        }
        if (t[28] != 0x00) {
            TRACE_DEVEL("CCA HMAC key token has unsupported format t[28]=%hhu != 0x00\n", t[26]);
            return FALSE;
        }
        *keytype = sec_hmac_key;
        *keybitsize = be16toh(*((uint16_t *)(t + CCA_HMAC_INTTOK_PAYLOAD_LENGTH_OFFSET)));
        /* this is not really the bitsize but the bitsize of the payload */
        if (*keybitsize < 80 || *keybitsize > 2432) {
            TRACE_DEVEL("CCA HMAC key token has invalid/unknown payload bit size %u\n", *keybitsize);
            return FALSE;
        }
        *mkvp = &t[10];
        return TRUE;
    }

    if (t[0] == 0x1f &&
        (t[CCA_RSA_INTTOK_PRIVKEY_OFFSET] == 0x30 ||
         t[CCA_RSA_INTTOK_PRIVKEY_OFFSET] == 0x31)) {
        /* internal secure cca private rsa key, ME or CRT format */
        uint16_t n, privsec_len;
        privsec_len = be16toh(*((uint16_t *)(t + CCA_RSA_INTTOK_PRIVKEY_OFFSET + 2)));
        if (CCA_RSA_INTTOK_PRIVKEY_OFFSET + privsec_len >= (int) tlen) {
            TRACE_DEVEL("CCA RSA key token has invalid priv section len or token size\n");
            return FALSE;
        }
        if (t[CCA_RSA_INTTOK_PRIVKEY_OFFSET + privsec_len] != 0x04) {
            TRACE_DEVEL("CCA RSA key token has invalid pub section marker\n");
            return FALSE;
        }
        n = be16toh(*((uint16_t *)(t + CCA_RSA_INTTOK_PRIVKEY_OFFSET + privsec_len + 8)));
        *keytype = sec_rsa_priv_key;
        *keybitsize = n;
        if (t[CCA_RSA_INTTOK_PRIVKEY_OFFSET] == 0x30)
            *mkvp = &t[CCA_RSA_INTTOK_PRIVKEY_OFFSET + 104];
        else
            *mkvp = &t[CCA_RSA_INTTOK_PRIVKEY_OFFSET + 116];
        return TRUE;
    }

    if (t[0] == 0x1e && t[CCA_RSA_INTTOK_HDR_LENGTH] == 0x04) {
        /* external RSA public key token */
        uint16_t n;
        n = be16toh(*((uint16_t *)(t + CCA_RSA_INTTOK_HDR_LENGTH + 8)));
        *keytype = sec_rsa_publ_key;
        *keybitsize = n;
        *mkvp = NULL;
        return TRUE;
    }

    if (t[0] == 0x1f && t[8] == 0x20) {
        /* internal secure cca private ecc key */
        uint16_t ec_curve_bits;
        if (t[8+4] != 0x01) {
            TRACE_DEVEL("CCA private ECC key token has invalid wrapping method 0x%02hhx\n", t[8+4]);
            return FALSE;
        }
        if (t[8+10] != 0x08) {
            TRACE_DEVEL("CCA private ECC key token has invalid key format 0x%02hhx\n", t[8+10]);
            return FALSE;
        }
        ec_curve_bits = be16toh(*((uint16_t *)(t + 8 + 12)));
        *keytype = sec_ecc_priv_key;
        *keybitsize = ec_curve_bits;
        *mkvp = &t[8+16];
        return TRUE;
    }

    if (t[0] == 0x1e && t[8] == 0x21) {
        /* external ECC public key token */
        uint16_t ec_curve_bits;
        ec_curve_bits = be16toh(*((uint16_t *)(t + 8 + 10)));
        *keytype = sec_ecc_publ_key;
        *keybitsize = ec_curve_bits;
        *mkvp = NULL;
        return TRUE;
    }

    if (t[0] == 0x1f && t[8] == 0x50) {
        /* internal secure cca private QSA key */
        uint16_t privsec_len;
        uint8_t algo_id;
        privsec_len = be16toh(*((uint16_t *)
                                (t + CCA_QSA_INTTOK_PRIVKEY_OFFSET + 2)));
        if (CCA_QSA_INTTOK_PRIVKEY_OFFSET + privsec_len > (int)tlen) {
            TRACE_DEVEL("CCA QSA key token has invalid priv section len or "
                        "token size\n");
            return FALSE;
        }
        algo_id = t[CCA_QSA_INTTOK_PRIVKEY_OFFSET +
                                CCA_QSA_INTTOK_ALGO_ID_OFFSET];
        switch (algo_id) {
        case CCA_QSA_ALGO_DILITHIUM_ROUND_2:
        case CCA_QSA_ALGO_DILITHIUM_ROUND_3:
            *keytype = sec_qsa_priv_key;
            break;
        default:
            TRACE_DEVEL("CCA QSA key token has invalid algorithm ID\n");
            return FALSE;
        }
        *keybitsize = 0; /* no chance to find out the key bit size */
        *mkvp = &t[CCA_QSA_INTTOK_PRIVKEY_OFFSET + CCA_QSA_INTTOK_MKVP_OFFSET];
        return TRUE;
    }

    if (t[0] == 0x1e && t[8] == 0x51) {
        /* external QSA public key token */
        uint16_t publsec_len;
        uint8_t algo_id;
        publsec_len = be16toh(*((uint16_t *)
                                (t + CCA_QSA_EXTTOK_PUBLKEY_OFFSET + 2)));
        if (CCA_QSA_EXTTOK_PUBLKEY_OFFSET + publsec_len > (int)tlen) {
            TRACE_DEVEL("CCA QSA key token has invalid publ section len or "
                        "token size\n");
            return FALSE;
        }
        algo_id = t[CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                    CCA_QSA_EXTTOK_ALGO_ID_OFFSET];
        switch (algo_id) {
        case CCA_QSA_ALGO_DILITHIUM_ROUND_2:
        case CCA_QSA_ALGO_DILITHIUM_ROUND_3:
            *keytype = sec_qsa_publ_key;
            break;
        default:
            TRACE_DEVEL("CCA QSA key token has invalid algorithm ID\n");
            return FALSE;
        }
        *keybitsize = 0; /* no chance to find out the key bit size */
        *mkvp = NULL;
        return TRUE;
    }

    return FALSE;
}

CK_RV check_expected_mkvp(STDLL_TokData_t *tokdata,
                          enum cca_token_type keytype,
                          const CK_BYTE *mkvp, CK_BBOOL *new_mk)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    const char *mktype;
    const CK_BYTE *expected_mkvp, *new_mkvp;

    if (new_mk != NULL)
        *new_mk = FALSE;

    switch (keytype) {
    case sec_des_data_key:
        expected_mkvp = cca_private->expected_sym_mkvp;
        new_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_SYM, NULL);
        mktype = "SYM";
        break;

    case sec_aes_data_key:
    case sec_aes_cipher_key:
    case sec_hmac_key:
        expected_mkvp = cca_private->expected_aes_mkvp;
        new_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_AES, NULL);
        mktype = "AES";
        break;

    case sec_rsa_priv_key:
    case sec_ecc_priv_key:
    case sec_qsa_priv_key:
        expected_mkvp = cca_private->expected_apka_mkvp;
        new_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_APKA, NULL);
        mktype = "APKA";
        break;

    case sec_rsa_publ_key:
    case sec_ecc_publ_key:
    case sec_qsa_publ_key:
        /* no MKVP checks for public keys */
        return CKR_OK;

    default:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    if (memcmp(mkvp, expected_mkvp, CCA_MKVP_LENGTH) != 0) {
        /* If an MK change operation is active, also allow the new MK */
        if (new_mkvp != NULL &&
            memcmp(mkvp, new_mkvp, CCA_MKVP_LENGTH) == 0) {
            TRACE_DEVEL("The key is wrapped by the new MK\n");
            if (new_mk != NULL)
                *new_mk = TRUE;
           return CKR_OK;
        }

        TRACE_ERROR("The key's master key verification pattern does not "
                    "match the expected CCA %s master key\n", mktype);
        TRACE_DEBUG_DUMP("MKVP of key:   ", (CK_BYTE *)mkvp, CCA_MKVP_LENGTH);
        TRACE_DEBUG_DUMP("Expected MKVP: ", (CK_BYTE *)expected_mkvp,
                         CCA_MKVP_LENGTH);
        OCK_SYSLOG(LOG_ERR, "The key's master key verification pattern does not "
                   "match the expected CCA %s master key\n", mktype);
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

/* Helper function: build attribute and update template */
CK_RV build_update_attribute(TEMPLATE * tmpl,
                             CK_ATTRIBUTE_TYPE type,
                             CK_BYTE * data, CK_ULONG data_len)
{
    CK_ATTRIBUTE *attr;
    CK_RV rv;

    if ((rv = build_attribute(type, data, data_len, &attr))) {
        TRACE_DEVEL("Build attribute for type=%lu failed, rv=0x%lx\n", type, rv);
        return rv;
    }
    if ((rv = template_update_attribute(tmpl, attr))) {
        TRACE_DEVEL("Template update for type=%lu failed, rv=0x%lx\n", type, rv);
        free(attr);
        return rv;
    }

    return CKR_OK;
}

static CK_RV cleanse_attribute(TEMPLATE *template,
                               CK_ATTRIBUTE_TYPE attr_type)
{
    CK_ATTRIBUTE *attr;

    if (template_attribute_get_non_empty(template, attr_type, &attr) != CKR_OK)
        return CKR_FUNCTION_FAILED;

    OPENSSL_cleanse(attr->pValue, attr->ulValueLen);

    return CKR_OK;
}

CK_RV token_specific_rng(STDLL_TokData_t * tokdata, CK_BYTE * output,
                         CK_ULONG bytes)
{
    long return_code, reason_code;
    unsigned char rule_array[CCA_KEYWORD_SIZE];
    CK_ULONG bytes_so_far = 0, num_bytes;
    long rule_array_count = 1, zero = 0;
    CK_RV rv;

    UNUSED(tokdata);

    memcpy(rule_array, "RANDOM  ", (size_t) CCA_KEYWORD_SIZE);

    while (bytes_so_far < bytes) {
        num_bytes = bytes - bytes_so_far;
        if (num_bytes > 8192)
            num_bytes = 8192;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNBRNGL(&return_code,
                         &reason_code,
                         NULL, NULL,
                         &rule_array_count, rule_array,
                         &zero, NULL,
                         (long *)&num_bytes, output + bytes_so_far);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBRNGL failed. return:%ld, reason:%ld\n",
                        return_code, reason_code);
            rv = CKR_FUNCTION_FAILED;
            return rv;
        }

        bytes_so_far += num_bytes;
    }

    return CKR_OK;
}

static CK_RV cca_resolve_lib_sym(void *hdl)
{
    #define LDSYM_VERIFY(handle, verb)                     \
    *(void **)(&dll_##verb) = dlsym(handle, #verb);        \
    if ((error = dlerror()) != NULL) {                     \
        OCK_SYSLOG(LOG_ERR,                                \
            "Loading verb %s failed: %s\n", #verb, error); \
        TRACE_ERROR("%s: Loading verb %s failed: %s\n",    \
            __func__, #verb, error);                       \
        return CKR_FUNCTION_FAILED;                        \
    }

    char *error = NULL;

    dlerror();                  /* Clear existing error */

    LDSYM_VERIFY(hdl, CSNBCKI);
    LDSYM_VERIFY(hdl, CSNBCKM);
    LDSYM_VERIFY(hdl, CSNBDKX);
    LDSYM_VERIFY(hdl, CSNBDKM);
    LDSYM_VERIFY(hdl, CSNBKEX);
    LDSYM_VERIFY(hdl, CSNBKGN);
    LDSYM_VERIFY(hdl, CSNBKGN2);
    LDSYM_VERIFY(hdl, CSNBKIM);
    LDSYM_VERIFY(hdl, CSNBKPI);
    LDSYM_VERIFY(hdl, CSNBKPI2);
    LDSYM_VERIFY(hdl, CSNBKSI);
    LDSYM_VERIFY(hdl, CSNBKRC);
    LDSYM_VERIFY(hdl, CSNBAKRC);
    LDSYM_VERIFY(hdl, CSNBKRD);
    LDSYM_VERIFY(hdl, CSNBKRL);
    LDSYM_VERIFY(hdl, CSNBKRR);
    LDSYM_VERIFY(hdl, CSNBKRW);
    LDSYM_VERIFY(hdl, CSNDKRC);
    LDSYM_VERIFY(hdl, CSNDKRD);
    LDSYM_VERIFY(hdl, CSNDKRL);
    LDSYM_VERIFY(hdl, CSNDKRR);
    LDSYM_VERIFY(hdl, CSNDKRW);
    LDSYM_VERIFY(hdl, CSNBKYT);
    LDSYM_VERIFY(hdl, CSNBKYTX);
    LDSYM_VERIFY(hdl, CSNBKTC);
    LDSYM_VERIFY(hdl, CSNBKTC2);
    LDSYM_VERIFY(hdl, CSNBKTR);
    LDSYM_VERIFY(hdl, CSNBRNG);
    LDSYM_VERIFY(hdl, CSNBRNGL);
    LDSYM_VERIFY(hdl, CSNBSAE);
    LDSYM_VERIFY(hdl, CSNBSAD);
    LDSYM_VERIFY(hdl, CSNBDEC);
    LDSYM_VERIFY(hdl, CSNBENC);
    LDSYM_VERIFY(hdl, CSNBMGN);
    LDSYM_VERIFY(hdl, CSNBMVR);
    LDSYM_VERIFY(hdl, CSNBKTB);
    LDSYM_VERIFY(hdl, CSNBKTB2);
    LDSYM_VERIFY(hdl, CSNDPKG);
    LDSYM_VERIFY(hdl, CSNDPKB);
    LDSYM_VERIFY(hdl, CSNBOWH);
    LDSYM_VERIFY(hdl, CSNDPKI);
    LDSYM_VERIFY(hdl, CSNDDSG);
    LDSYM_VERIFY(hdl, CSNDDSV);
    LDSYM_VERIFY(hdl, CSNDKTC);
    LDSYM_VERIFY(hdl, CSNDPKX);
    LDSYM_VERIFY(hdl, CSNDSYI);
    LDSYM_VERIFY(hdl, CSNDSYI2);
    LDSYM_VERIFY(hdl, CSNDSYX);
    LDSYM_VERIFY(hdl, CSUACFQ);
    LDSYM_VERIFY(hdl, CSUACFC);
    LDSYM_VERIFY(hdl, CSNDSBC);
    LDSYM_VERIFY(hdl, CSNDSBD);
    LDSYM_VERIFY(hdl, CSUALCT);
    LDSYM_VERIFY(hdl, CSUAACM);
    LDSYM_VERIFY(hdl, CSUAACI);
    LDSYM_VERIFY(hdl, CSNDPKH);
    LDSYM_VERIFY(hdl, CSNDPKR);
    LDSYM_VERIFY(hdl, CSUAMKD);
    LDSYM_VERIFY(hdl, CSNDRKD);
    LDSYM_VERIFY(hdl, CSNDRKL);
    LDSYM_VERIFY(hdl, CSNDSYG);
    LDSYM_VERIFY(hdl, CSNBPTR);
    LDSYM_VERIFY(hdl, CSNBCPE);
    LDSYM_VERIFY(hdl, CSNBCPA);
    LDSYM_VERIFY(hdl, CSNBPGN);
    LDSYM_VERIFY(hdl, CSNBPVR);
    LDSYM_VERIFY(hdl, CSNBDKG);
    LDSYM_VERIFY(hdl, CSNBEPG);
    LDSYM_VERIFY(hdl, CSNBCVE);
    LDSYM_VERIFY(hdl, CSNBCSG);
    LDSYM_VERIFY(hdl, CSNBCSV);
    LDSYM_VERIFY(hdl, CSNBCVG);
    LDSYM_VERIFY(hdl, CSNBKTP);
    LDSYM_VERIFY(hdl, CSNDPKE);
    LDSYM_VERIFY(hdl, CSNDPKD);
    LDSYM_VERIFY(hdl, CSNBPEX);
    LDSYM_VERIFY(hdl, CSNBPEXX);
    LDSYM_VERIFY(hdl, CSUARNT);
    LDSYM_VERIFY(hdl, CSNBCVT);
    LDSYM_VERIFY(hdl, CSNBMDG);
    LDSYM_VERIFY(hdl, CSUACRA);
    LDSYM_VERIFY(hdl, CSUACRD);
    LDSYM_VERIFY(hdl, CSNBTRV);
    LDSYM_VERIFY(hdl, CSNBSKY);
    LDSYM_VERIFY(hdl, CSNBSPN);
    LDSYM_VERIFY(hdl, CSNBPCU);
    LDSYM_VERIFY(hdl, CSNDEDH);
    LDSYM_VERIFY(hdl, CSUAPRB);
    LDSYM_VERIFY(hdl, CSNDTBC);
    LDSYM_VERIFY(hdl, CSNDRKX);
    LDSYM_VERIFY(hdl, CSNBKET);
    LDSYM_VERIFY(hdl, CSNBHMG);
    LDSYM_VERIFY(hdl, CSNBHMV);
    LDSYM_VERIFY(hdl, CSNBCTT2);
    LDSYM_VERIFY(hdl, CSUACFV);
    LDSYM_VERIFY(hdl, CSNBRKA);
    LDSYM_VERIFY(hdl, CSNBKTR2);

    return CKR_OK;
}

/* Called during token_specific_init() , no need to obtain CCA adapter lock */
static CK_RV cca_get_version(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned char exit_data[4] = { 0, };
    unsigned char version_data[20] = { 0 };
    long return_code, reason_code;
    long version_data_length;
    long exit_data_len = 0;
    char date[20];

    /* Version data format of CSUACFV is different on non-s390x- platforms */
#if !defined(__s390__)
    const char *verstrfmt = "%u.%u.%uc %s";
#else
    const char *verstrfmt = "%u.%u.%uz%s";
#endif

    /* Get CCA host library version */
    version_data_length = sizeof(version_data);
    dll_CSUACFV(&return_code, &reason_code,
                &exit_data_len, exit_data,
                &version_data_length, version_data);
    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFV failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    /* CSUACFV returns a null-terminated version string */
    TRACE_DEVEL("CCA Version string: %s\n", version_data);

    if (sscanf((char *)version_data, verstrfmt,
               &cca_private->cca_lib_version.ver,
               &cca_private->cca_lib_version.rel,
               &cca_private->cca_lib_version.mod, date) != 4) {
        TRACE_ERROR("CCA library version is invalid: %s\n", version_data);
        return CKR_FUNCTION_FAILED;
    }

    if (cca_private->cca_lib_version.ver < CCA_MIN_VERSION ||
        (cca_private->cca_lib_version.ver == CCA_MIN_VERSION &&
         cca_private->cca_lib_version.rel < CCA_MIN_RELEASE)) {
        TRACE_ERROR("The CCA host library version is too old: %u.%u.%u, "
                    "required: %u.%u or later\n",
                    cca_private->cca_lib_version.ver, cca_private->cca_lib_version.rel,
                    cca_private->cca_lib_version.mod, CCA_MIN_VERSION, CCA_MIN_RELEASE);
        OCK_SYSLOG(LOG_ERR,"The CCA host library version is too old: %u.%u.%u, "
                   "required: %u.%u or later\n",
                   cca_private->cca_lib_version.ver, cca_private->cca_lib_version.rel,
                   cca_private->cca_lib_version.mod, CCA_MIN_VERSION, CCA_MIN_RELEASE);
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

/*
 * Called from within cca_iterate_adapters() handler function, thus no need to
 * obtain  CCA adapter lock
 */
CK_RV cca_get_adapter_serial_number(char *serialno)
{
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, verb_data_length;

    memcpy(rule_array, "STATCRD2", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    verb_data_length = 0;
    dll_CSUACFQ(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &verb_data_length, NULL);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFQ (STATCRD2) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(serialno, &rule_array[CCA_STATCRD2_SERIAL_NUMBER_OFFSET],
           CCA_SERIALNO_LENGTH);
    serialno[CCA_SERIALNO_LENGTH] = '\0';

    return CKR_OK;
}

/*
 * Called from within cca_iterate_adapters() handler function, thus no need to
 * obtain  CCA adapter lock
 */
CK_RV cca_get_mk_state(enum cca_mk_type mk_type,
                       enum cca_cmk_state *cur,
                       enum cca_nmk_state *new)
{
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, verb_data_length;
    char *cmk, *nmk;

    switch (mk_type) {
    case CCA_MK_SYM:
        memcpy(rule_array, "STATCCAE", CCA_KEYWORD_SIZE);
        rule_array_count = 1;
        break;
    case CCA_MK_AES:
        memcpy(rule_array, "STATAES ", CCA_KEYWORD_SIZE);
        rule_array_count = 1;
        break;
    case CCA_MK_APKA:
        memcpy(rule_array, "STATAPKA", CCA_KEYWORD_SIZE);
        rule_array_count = 1;
        break;
    default:
        return CKR_ARGUMENTS_BAD;
    }

    verb_data_length = 0;
    dll_CSUACFQ(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &verb_data_length, NULL);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFQ (%s) failed. return:%ld, reason:%ld\n",
                    rule_array, return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    switch (mk_type) {
    case CCA_MK_SYM:
        cmk = (char *)&rule_array[CCA_STATCCAE_SYM_CMK_OFFSET];
        nmk = (char *)&rule_array[CCA_STATCCAE_SYM_NMK_OFFSET];
        break;
    case CCA_MK_AES:
        cmk = (char *)&rule_array[CCA_STATAES_AES_CMK_OFFSET];
        nmk = (char *)&rule_array[CCA_STATAES_AES_NMK_OFFSET];
        break;
    case CCA_MK_APKA:
        cmk = (char *)&rule_array[CCA_STATAPKA_APKA_CMK_OFFSET];
        nmk = (char *)&rule_array[CCA_STATAPKA_APKA_NMK_OFFSET];
        break;
    default:
        return CKR_ARGUMENTS_BAD;
    }

    cmk[1] = '\0';
    nmk[1] = '\0';

    if (cur != NULL) {
        if (sscanf(cmk, "%d", (int *)cur) != 1) {
            TRACE_ERROR("Bad CMK status '%s'\n", cmk);
            return CKR_FUNCTION_FAILED;
        }
    }

    if (new != NULL) {
        if (sscanf(nmk, "%d", (int *)new) != 1) {
            TRACE_ERROR("Bad CMK status '%s'\n", nmk);
            return CKR_FUNCTION_FAILED;
        }
    }

    return CKR_OK;
}

/*
 * Called from within cca_iterate_adapters() handler function, thus no need to
 * obtain  CCA adapter lock
 */
CK_RV cca_get_mkvps(unsigned char *cur_sym, unsigned char *new_sym,
                    unsigned char *cur_aes, unsigned char *new_aes,
                    unsigned char *cur_apka, unsigned char *new_apka)
{
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    unsigned char verb_data[256] = { 0, };
    long return_code, reason_code, rule_array_count, verb_data_length;
    unsigned short *id;

    /* Get master key verification patterns */
    memset(rule_array, 0, sizeof(rule_array));
    memcpy(rule_array, "STATICSB", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    verb_data_length = sizeof(verb_data);
    dll_CSUACFQ(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &verb_data_length, verb_data);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFQ (STATICSB) failed . return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (cur_sym != NULL) {
        id = (unsigned short *)(verb_data + CCA_STATICSB_SYM_CMK_ID_OFFSET);
        if (be16toh(*id) != CCA_STATICSB_SYM_CMK_ID) {
            TRACE_ERROR("CSUACFQ (STATICSB) current SYM MKVP not available\n");
            return CKR_FUNCTION_FAILED;
        }

        memcpy(cur_sym, verb_data + CCA_STATICSB_SYM_CMK_MKVP_OFFSET,
               CCA_MKVP_LENGTH);
    }

    if (new_sym != NULL) {
        id = (unsigned short *)(verb_data + CCA_STATICSB_SYM_NMK_ID_OFFSET);
        if (be16toh(*id) != CCA_STATICSB_SYM_NMK_ID) {
            TRACE_ERROR("CSUACFQ (STATICSB) new SYM MKVP not available\n");
            return CKR_FUNCTION_FAILED;
        }

        memcpy(new_sym, verb_data + CCA_STATICSB_SYM_NMK_MKVP_OFFSET,
               CCA_MKVP_LENGTH);
    }

    if (cur_aes != NULL) {
        id = (unsigned short *)(verb_data + CCA_STATICSB_AES_CMK_ID_OFFSET);
        if (be16toh(*id) != CCA_STATICSB_AES_CMK_ID) {
            TRACE_ERROR("CSUACFQ (STATICSB) current AES MKVP not available\n");
            return CKR_FUNCTION_FAILED;
        }

        memcpy(cur_aes, verb_data + CCA_STATICSB_AES_CMK_MKVP_OFFSET,
               CCA_MKVP_LENGTH);
    }

    if (new_aes != NULL) {
        id = (unsigned short *)(verb_data + CCA_STATICSB_AES_NMK_ID_OFFSET);
        if (be16toh(*id) != CCA_STATICSB_AES_NMK_ID) {
            TRACE_ERROR("CSUACFQ (STATICSB) new AES MKVP not available\n");
            return CKR_FUNCTION_FAILED;
        }

        memcpy(new_aes, verb_data + CCA_STATICSB_AES_NMK_MKVP_OFFSET,
               CCA_MKVP_LENGTH);
    }

    if (cur_apka != NULL) {
        id = (unsigned short *)(verb_data + CCA_STATICSB_APKA_CMK_ID_OFFSET);
        if (be16toh(*id) != CCA_STATICSB_APKA_CMK_ID) {
            TRACE_ERROR("CSUACFQ (STATICSB) current APKA MKVP not available\n");
            return CKR_FUNCTION_FAILED;
        }

        memcpy(cur_apka, verb_data + CCA_STATICSB_APKA_CMK_MKVP_OFFSET,
               CCA_MKVP_LENGTH);
    }

    if (new_apka != NULL) {
        id = (unsigned short *)(verb_data + CCA_STATICSB_APKA_NMK_ID_OFFSET);
        if (be16toh(*id) != CCA_STATICSB_APKA_NMK_ID) {
            TRACE_ERROR("CSUACFQ (STATICSB) new APKA MKVP not available\n");
            return CKR_FUNCTION_FAILED;
        }

        memcpy(new_apka, verb_data + CCA_STATICSB_APKA_NMK_MKVP_OFFSET,
               CCA_MKVP_LENGTH);
    }

    return CKR_OK;
}

static CK_RV cca_cmp_mkvp(unsigned char mkvp[CCA_MKVP_LENGTH],
                          unsigned char exp_mkvp[CCA_MKVP_LENGTH],
                          unsigned char *new_mkvp,
                          const char *mktype, const char *adapter,
                          unsigned short card, unsigned short domain,
                          CK_BBOOL expected_mkvps_set)
{
    /*
     * If an MK change operation is pending, the current MK may already
     * be the new MK of the operation.
     */
    if (new_mkvp != NULL &&
        memcmp(mkvp, new_mkvp, CCA_MKVP_LENGTH) == 0) {
        TRACE_DEVEL("CCA %s master key on adapter %s (%02X.%04X) has "
                    "the new MK\n", mktype, adapter, card, domain);
        return CKR_OK;
    }

    if (expected_mkvps_set == FALSE &&
        memcmp(exp_mkvp, cca_zero_mkvp, CCA_MKVP_LENGTH) == 0) {
        /* zero expected MKVP, copy current one */
        memcpy(exp_mkvp, mkvp, CCA_MKVP_LENGTH);
    } else {
        if (memcmp(mkvp, exp_mkvp, CCA_MKVP_LENGTH) != 0) {
            TRACE_ERROR("CCA %s master key on adapter %s (%02X.%04X) does not "
                        "match the %s master key\n", mktype, adapter, card,
                        domain, expected_mkvps_set ? "expected" : "other APQN's");
            OCK_SYSLOG(LOG_ERR, "CCA %s master key on adapter %s (%02X.%04X) does "
                       "not match the %s master key\n", mktype, adapter, card,
                       domain, expected_mkvps_set ? "expected" : "other APQN's");
            return CKR_DEVICE_ERROR;
        }
    }

    return CKR_OK;
}

static CK_RV cca_get_and_check_mkvps(STDLL_TokData_t *tokdata,
                                     const char *adapter,
                                     unsigned short card,
                                     unsigned short domain,
                                     void *private)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    char serialno[CCA_SERIALNO_LENGTH + 1];
    unsigned char sym_mkvp[CCA_MKVP_LENGTH];
    unsigned char sym_new_mkvp[CCA_MKVP_LENGTH];
    unsigned char aes_mkvp[CCA_MKVP_LENGTH];
    unsigned char aes_new_mkvp[CCA_MKVP_LENGTH];
    unsigned char apka_mkvp[CCA_MKVP_LENGTH];
    unsigned char apka_new_mkvp[CCA_MKVP_LENGTH];
    unsigned char *op_sym_mkvp, *op_aes_mkvp, *op_apka_mkvp;
    unsigned int sym_op_idx = 0, aes_op_idx = 0, apka_op_idx = 0;
    enum cca_cmk_state mk_state;
    enum cca_nmk_state sym_new_state, aes_new_state, apka_new_state;
    CK_RV rc, rc2 = CKR_OK;

    UNUSED(private);

#if defined(_AIX)
    /* populate program_invocation_short_name for later use */
    populate_progname();
#endif

    /* Get current adapter serial number */
    rc = cca_get_adapter_serial_number(serialno);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_get_adapter_serial_number failed for %s (%02X.%04X)\n",
                    adapter, card, domain);
        return rc;
    }
    TRACE_DEVEL("%s (%02X.%04X) serialno: %s\n", adapter, card, domain,
                serialno);

    /* Get status of SYM master key (DES, 3DES keys) */
    rc = cca_get_mk_state(CCA_MK_SYM, &mk_state, &sym_new_state);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_get_mk_state (SYM) failed for %s (%02X.%04X)\n",
                    adapter, card, domain);
        return rc;
    }

    /* Ensure the master key is set in the card */
    if (mk_state != CCA_CMK_STATUS_FULL) {
        TRACE_ERROR("CCA SYM master key is not yet loaded on adapter %s (%02X.%04X)\n",
                    adapter, card, domain);
        OCK_SYSLOG(LOG_ERR,
                   "CCA SYM master key is not yet loaded on adapter %s (%02X.%04X)\n",
                   adapter, card, domain);
        return CKR_DEVICE_ERROR;
    }

    /* Get status of AES master key (AES, HMAC keys) */
    rc = cca_get_mk_state(CCA_MK_AES, &mk_state, &aes_new_state);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_get_mk_state (AES) failed for %s (%02X.%04X)\n",
                    adapter, card, domain);
        return rc;
    }

    /* Ensure the master key is set in the card */
    if (mk_state != CCA_CMK_STATUS_FULL) {
        TRACE_ERROR("CCA AES master key is not yet loaded on adapter %s (%02X.%04X)\n",
                    adapter, card, domain);
        OCK_SYSLOG(LOG_ERR,
                   "CCA AES master key is not yet loaded on adapter %s (%02X.%04X)\n",
                   adapter, card, domain);
        return CKR_DEVICE_ERROR;
    }

    /* Get status of APKA master key (RSA and ECC keys) */
    rc = cca_get_mk_state(CCA_MK_APKA, &mk_state, &apka_new_state);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_get_mk_state (APKA) failed for %s (%02X.%04X)\n",
                    adapter, card, domain);
        return rc;
    }

    /* Ensure the master key is set in the card */
    if (mk_state != CCA_CMK_STATUS_FULL) {
        TRACE_ERROR("CCA APKA master key is not yet loaded on adapter %s (%02X.%04X)\n",
                    adapter, card, domain);
        OCK_SYSLOG(LOG_ERR,
                   "CCA APKA master key is not yet loaded on adapter %s (%02X.%04X)\n",
                   adapter, card, domain);
        return CKR_DEVICE_ERROR;
    }

    /* Get master key verification patterns */
    rc = cca_get_mkvps(sym_mkvp, sym_new_mkvp, aes_mkvp, aes_new_mkvp,
                       apka_mkvp, apka_new_mkvp);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_get_mkvps failed for %s (%02X.%04X)\n",
                    adapter, card, domain);
        return rc;
    }

    TRACE_DEBUG("Master key verification patterns for %s (%02X.%04X)\n",
                adapter, card, domain);
    TRACE_DEBUG_DUMP("SYM CUR MKVP:  ", sym_mkvp, CCA_MKVP_LENGTH);
    if (sym_new_state == CCA_NMK_STATUS_FULL) {
        TRACE_DEBUG_DUMP("SYM NEW MKVP:  ", sym_new_mkvp, CCA_MKVP_LENGTH);
    }
    TRACE_DEBUG_DUMP("AES CUR MKVP:  ", aes_mkvp, CCA_MKVP_LENGTH);
    if (aes_new_state == CCA_NMK_STATUS_FULL) {
        TRACE_DEBUG_DUMP("AES NEW MKVP:  ", aes_new_mkvp, CCA_MKVP_LENGTH);
    }
    TRACE_DEBUG_DUMP("APKA CUR MKVP: ", apka_mkvp, CCA_MKVP_LENGTH);
    if (apka_new_state == CCA_NMK_STATUS_FULL) {
        TRACE_DEBUG_DUMP("APKA NEW MKVP: ", apka_new_mkvp, CCA_MKVP_LENGTH);
    }

    op_sym_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_SYM,
                                                 &sym_op_idx);
    op_aes_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_AES,
                                                 &aes_op_idx);
    op_apka_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_APKA,
                                                  &apka_op_idx);

    /* Current MK can either be expected one, or new from operation (if any) */
    rc = cca_cmp_mkvp(sym_mkvp, cca_private->expected_sym_mkvp, op_sym_mkvp,
                      "SYM", adapter, card, domain,
                      cca_private->expected_sym_mkvp_set);
    rc |= cca_cmp_mkvp(aes_mkvp, cca_private->expected_aes_mkvp, op_aes_mkvp,
                       "AES", adapter, card, domain,
                       cca_private->expected_aes_mkvp_set);
    rc |= cca_cmp_mkvp(apka_mkvp, cca_private->expected_apka_mkvp, op_apka_mkvp,
                       "APKA", adapter, card, domain,
                       cca_private->expected_apka_mkvp_set);

    /*
     * If new MK is set, it must be the one from the MK change operation(s).
     * If new MK is not set, the current MK must be the expected new MK of
     * the operation(s). For this case, report error only if not within the
     * pkcshsm_mk_change tool process. Otherwise the MK change operation could
     * not be canceled when the new MK register has already been cleared by
     * the HSM admin.
     */
    if (op_sym_mkvp != NULL) {
        rc2 |= cca_cmp_mkvp(sym_new_state == CCA_NMK_STATUS_FULL ?
                                                sym_new_mkvp : sym_mkvp,
                           op_sym_mkvp, NULL,
                           sym_new_state == CCA_NMK_STATUS_FULL ?
                                                "SYM NEW" : "SYM CURRENT",
                           adapter, card, domain, TRUE);
        if (sym_new_state != CCA_NMK_STATUS_FULL &&
            strcmp(program_invocation_short_name, "pkcshsm_mk_change") == 0)
            rc2 = CKR_OK;
        rc |= rc2;
    }
    if (op_aes_mkvp != NULL) {
        rc2 |= cca_cmp_mkvp(aes_new_state == CCA_NMK_STATUS_FULL ?
                                                aes_new_mkvp : aes_mkvp,
                           op_aes_mkvp, NULL,
                           aes_new_state == CCA_NMK_STATUS_FULL ?
                                                "AES NEW" : "AES CURRENT",
                           adapter, card, domain, TRUE);
        if (aes_new_state != CCA_NMK_STATUS_FULL &&
            strcmp(program_invocation_short_name, "pkcshsm_mk_change") == 0)
            rc2 = CKR_OK;
        rc |= rc2;
    }
    if (op_apka_mkvp != NULL) {
        rc2 |= cca_cmp_mkvp(apka_new_state == CCA_NMK_STATUS_FULL ?
                                                apka_new_mkvp : apka_mkvp,
                           op_apka_mkvp, NULL,
                           apka_new_state == CCA_NMK_STATUS_FULL ?
                                                "APKA NEW" : "APKA CURRENT",
                           adapter, card, domain, TRUE);
        if (apka_new_state != CCA_NMK_STATUS_FULL &&
            strcmp(program_invocation_short_name, "pkcshsm_mk_change") == 0)
            rc2 = CKR_OK;
        rc |= rc2;
    }

    /*
     * If an MK change operation is active, the current APQN must be part
     * of each operation.
     */
    if (op_sym_mkvp != NULL &&
        !hsm_mk_change_apqns_find(
                            cca_private->mk_change_ops[sym_op_idx].apqns,
                            cca_private->mk_change_ops[sym_op_idx].num_apqns,
                            card, domain)) {
        TRACE_ERROR("APQN %02X.%04X is used by the CCA token, but it is "
                    "not part of the active MK change operation '%s'\n",
                    card, domain,
                    cca_private->mk_change_ops[sym_op_idx].mk_change_op);
        OCK_SYSLOG(LOG_ERR, "APQN %02X.%04X is used by the CCA token, but "
                   "it is not part of the active MK change operation '%s'\n",
                   card, domain,
                   cca_private->mk_change_ops[sym_op_idx].mk_change_op);
        rc |= CKR_DEVICE_ERROR;
    }

    if (op_aes_mkvp != NULL &&
        !hsm_mk_change_apqns_find(
                            cca_private->mk_change_ops[aes_op_idx].apqns,
                            cca_private->mk_change_ops[aes_op_idx].num_apqns,
                            card, domain)) {
        TRACE_ERROR("APQN %02X.%04X is used by the CCA token, but it is "
                    "not part of the active MK change operation '%s'\n",
                    card, domain,
                    cca_private->mk_change_ops[aes_op_idx].mk_change_op);
        OCK_SYSLOG(LOG_ERR, "APQN %02X.%04X is used by the CCA token, but "
                   "it is not part of the active MK change operation '%s'\n",
                   card, domain,
                   cca_private->mk_change_ops[aes_op_idx].mk_change_op);
        rc |= CKR_DEVICE_ERROR;
    }

    if (op_apka_mkvp != NULL &&
        !hsm_mk_change_apqns_find(
                            cca_private->mk_change_ops[apka_op_idx].apqns,
                            cca_private->mk_change_ops[apka_op_idx].num_apqns,
                            card, domain)) {
        TRACE_ERROR("APQN %02X.%04X is used by the CCA token, but it is "
                    "not part of the active MK change operation '%s'\n",
                    card, domain,
                    cca_private->mk_change_ops[apka_op_idx].mk_change_op);
        OCK_SYSLOG(LOG_ERR, "APQN %02X.%04X is used by the CCA token, but "
                   "it is not part of the active MK change operation '%s'\n",
                   card, domain,
                   cca_private->mk_change_ops[apka_op_idx].mk_change_op);
        rc |= CKR_DEVICE_ERROR;
    }

    if (rc != CKR_OK)
       return CKR_DEVICE_ERROR;

    return CKR_OK;
}

static CK_RV cca_get_current_domain(unsigned short *domain)
{
    /*
     * Only CCA on Linux on IBM Z supports CSU_DEFAULT_DOMAIN, all others
     * support only one domain (i.e. domain 0).
     */
#if !defined(__s390__)
    *domain = 0;
#else
    const char *val;
    unsigned int num;
    char fname[290];
    char buf[250];
    CK_RV rc;

    val = getenv(CCA_DEFAULT_DOMAIN_ENVAR);
    if (val == NULL) {
        /* Get default domain from AP bus */
        sprintf(fname, "%s/ap_domain", SYSFS_BUS_AP);
        rc = file_fgets(fname, buf, sizeof(buf));
        if (rc != CKR_OK)
            return rc;
        if (sscanf(buf, "%u", &num) != 1)
            return CKR_FUNCTION_FAILED;

        *domain = num;
        return CKR_OK;
    }

    if (strcmp(val, CCA_DOMAIN_ANY) == 0) {
        /* DOM-ANY mode, can not determine single domain */
        return CKR_DEVICE_ERROR;
    }

    /* domain specified */
    if (sscanf(val, "%u", &num) != 1)
        return CKR_FUNCTION_FAILED;

    *domain = num;
#endif
    return CKR_OK;
}

static CK_RV cca_get_current_card(unsigned short *card, char *serialret)
{
    char serialno[CCA_SERIALNO_LENGTH + 1];
#if defined(__s390__)
    DIR *d;
    struct dirent *de;
    regex_t reg_buf;
    regmatch_t pmatch[1];
    char fname[290];
    char buf[250];
    unsigned long val;
#endif
    CK_BBOOL found = FALSE;
    CK_RV rc;

    /* Get serial number of current adapter */
    rc = cca_get_adapter_serial_number(serialno);
    if (rc != CKR_OK)
        return rc;

    TRACE_DEVEL("serialno: %s\n", serialno);

    /* Only Linux on IBM Z supports to find the cards via sysfs, for all
     * others the default card is always the first card (i.e. card number 0).
     */
#if !defined(__s390__)
    *card = 0;
    found = TRUE;
#else
    if (regcomp(&reg_buf, REGEX_CARD_PATTERN, REG_EXTENDED) != 0) {
        TRACE_ERROR("Failed to compile regular expression '%s'\n",
                    REGEX_CARD_PATTERN);
        return CKR_FUNCTION_FAILED;
    }

    /* Find card with that serial number in Sysfs */
    d = opendir(SYSFS_DEVICES_AP);
    if (d == NULL) {
        TRACE_ERROR("Directory %s is not available\n", SYSFS_DEVICES_AP);
        regfree(&reg_buf);
        return CKR_FUNCTION_FAILED;
    }

    while ((de = readdir(d)) != NULL) {
        if (regexec(&reg_buf, de->d_name, (size_t) 1, pmatch, 0) == 0) {
            /* Check for CCA cards only */
            sprintf(fname, "%s/%s/ap_functions", SYSFS_DEVICES_AP, de->d_name);
            rc = file_fgets(fname, buf, sizeof(buf));
            if (rc != CKR_OK)
                continue;
            if (sscanf(buf, "%lx", &val) != 1)
                val = 0x00000000;
            if ((val & MASK_COPRO) == 0)
                continue;

            sprintf(fname, "%s/%s/serialnr", SYSFS_DEVICES_AP, de->d_name);
            rc = file_fgets(fname, buf, sizeof(buf));
            if (rc != CKR_OK)
                continue;
            if (strcmp(buf, serialno) != 0)
                continue;

            if (sscanf(de->d_name + 4, "%lx", &val) != 1)
                continue;

            found = TRUE;
            *card = val;
            break;
        }
    }

    closedir(d);
    regfree(&reg_buf);
#endif /* __s390__ */

    if (found && serialret != NULL)
        strcpy(serialret, serialno);

    if (found)
        TRACE_DEVEL("Current card is %02x with serialno %s\n", *card, serialno);
    else
        TRACE_ERROR("Card with serialno %s not found in sysfs\n", serialno);

    return found ? CKR_OK : CKR_DEVICE_ERROR;
}

/*
 * Must NOT hold the CCA adapter lock when called !
 * May obtain the WRITE lock during iteration processing, but returns without
 * holding a lock.
 * The handler function is called when a single adapter/domain is selected,
 * and the WRITE lock may be held, thus the handler function must not obtain
 * an CCA adapter lock.
 */
static CK_RV cca_iterate_domains(STDLL_TokData_t *tokdata, const char *device,
                                 CK_RV (*cb)(STDLL_TokData_t *tokdata,
                                             const char *adapter,
                                             unsigned short card,
                                             unsigned short domain,
                                             void *private),
                                 void *cb_private)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, device_name_len;
    unsigned char *device_name;
    unsigned short card, domain = 0;
    unsigned int i, num_found = 0;
    CK_RV rc2, rc = CKR_OK;
    char serialno[CCA_SERIALNO_LENGTH + 1] = { 0 };

    if (cca_private->dom_any == FALSE) {
        rc = cca_get_current_domain(&domain);
        if (rc != CKR_OK)
            return rc;
    }

    if (cca_private->dev_any == FALSE) {
        rc = cca_get_current_card(&card, serialno);
        if (rc != CKR_OK)
            return rc;
    }

    /*
     * Obtain the CCA adapter WRITE lock if DOM-ANY and release it only after
     * domain selection has been turned back to default.
     */
    if (cca_private->dom_any) {
        if (pthread_rwlock_wrlock(&cca_adapter_rwlock) != 0) {
            TRACE_DEVEL("CCA adapter WR-Lock failed.\n");
            return CKR_CANT_LOCK;
        }
    }

    for (i = 0; i < cca_private->num_usagedoms; i++) {
        /* Allocate the adapter based on device or serialno and domain */
        if (cca_private->dev_any) {
            memcpy(rule_array, "DEVICE  ", CCA_KEYWORD_SIZE);
            rule_array_count = 1;
            device_name_len = strlen(device);
            device_name = (unsigned char *)device;
        } else {
            memcpy(rule_array, "SERIAL  ", CCA_KEYWORD_SIZE);
            rule_array_count = 1;
            device_name_len = strlen(serialno);
            device_name = (unsigned char *)serialno;
        }

        if (cca_private->dom_any) {
            sprintf((char *)(rule_array + CCA_KEYWORD_SIZE), "DOMN%04u",
                    cca_private->usage_domains[i]);
            rule_array_count = 2;

            domain = cca_private->usage_domains[i];
        }

        dll_CSUACRA(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    &device_name_len, device_name);

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSUACRA failed for %s domain %x. return:%ld, reason:%ld\n",
                        device_name, domain, return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
            break;
        }

        if (cca_private->dev_any) {
            rc2 = cca_get_current_card(&card, NULL);
            if (rc2 != CKR_OK) {
                if (rc2 == CKR_FUNCTION_FAILED) /* device not avail., ignore */
                    rc2 = CKR_OK;
                else
                    rc |= rc2;
                goto deallocate;
            }
        }

        rc2 = cb(tokdata, device, card, domain, cb_private);
        if (rc2 == CKR_OK)
            num_found++;
        if (rc2 == CKR_FUNCTION_FAILED) /* device not available, ignore */
            rc2 = CKR_OK;
        rc |= rc2;

deallocate:
        /* Deallocate the adapter */
        if (cca_private->dom_any) {
            memcpy(rule_array + CCA_KEYWORD_SIZE, "DOMN-DEF", CCA_KEYWORD_SIZE);
            rule_array_count = 2;
        }

        dll_CSUACRD(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    &device_name_len, device_name);

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSUACRD failed for %s domain %x. return:%ld, reason:%ld\n",
                        device_name, domain, return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
            break;
        }

        if (cca_private->dom_any == FALSE)
            break;
    }

    /* Release the CCA adapter WRITE lock now if DOM-ANY */
    if (cca_private->dom_any) {
        if (pthread_rwlock_unlock(&cca_adapter_rwlock) != 0) {
            TRACE_DEVEL("CCA adapter Unlock failed.\n");
            return CKR_CANT_LOCK;
        }
    }

    if (rc != CKR_OK)
        return CKR_DEVICE_ERROR;
    if (num_found == 0) /* none available */
        return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

/*
 * Must NOT hold the CCA adapter lock when called !
 * May obtain the WRITE lock during iteration processing, but returns without
 * holding a lock.
 * The handler function is called when a single adapter/domain is selected,
 * and the WRITE lock may be held, thus the handler function must not obtain
 * an CCA adapter lock.
 */
CK_RV cca_iterate_adapters(STDLL_TokData_t *tokdata,
                           CK_RV (*cb)(STDLL_TokData_t *tokdata,
                                       const char *adapter,
                                       unsigned short card,
                                       unsigned short domain,
                                       void *private),
                           void *cb_private)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned int adapter, num_found = 0;
    char device_name[9] = {0, };
    unsigned short card, domain;
    CK_RV rc, rc2;

    if (cca_private->dev_any == FALSE && cca_private->dom_any == FALSE) {
        /* CCA default adapter and domain selection */
        rc = cca_get_current_card(&card, NULL);
        if (rc != CKR_OK)
            return rc;

        rc = cca_get_current_domain(&domain);
        if (rc != CKR_OK)
            return rc;

        rc = cb(tokdata, "DEFAULT", card, domain, cb_private);
        if (rc != CKR_OK)
            return rc;
    } else if (cca_private->dev_any == FALSE) {
        /* CCA default adapter selection, but domain ANY */
        rc = cca_iterate_domains(tokdata, "DEFAULT", cb, cb_private);
        if (rc != CKR_OK)
            return rc;
    } else {
        /* Device ANY and domain ANY or default */
        for (adapter = 1, rc = CKR_OK; adapter <= cca_private->num_adapters;
                                                                 adapter++) {
            sprintf(device_name, "CRP%02u", adapter);

            rc2 = cca_iterate_domains(tokdata, device_name, cb, cb_private);
            if (rc2 == CKR_FUNCTION_FAILED) /* adapter not available, ignore */
                rc2 = CKR_OK;
            if (rc2 == CKR_OK)
                num_found++;
            rc |= rc2;
        }
        if (rc != CKR_OK)
            return CKR_DEVICE_ERROR;
        if (num_found == 0)
            return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV cca_get_adapter_domain_selection_infos(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, verb_data_length;
#if defined(__s390__)
    unsigned int i;
    const char *val;
#endif

    /*
     * Only Linux on IBM Z supports the AUTOSELECT option with adapter/domain
     * selection using CSU_DEFAULT_ADAPTER with 'DEV-ANY' and/or
     * CSU_DEFAULT_DOMAIN with 'DOM-ANY'. All other platforms only support
     * selection of one distinct adapter, and no domain selection at all.
     * Enable the AUTOSELECT (i.e. 'DEV-ANY' / 'DOM-ANY') support code
     * only for CCA on Linux on IBM Z.
     */
#if defined(__s390__)
    /* Check if adapter and/or domain auto-selection is used */
    val = getenv(CCA_DEFAULT_ADAPTER_ENVAR);
    if (val != NULL && strcmp(val, CCA_DEVICE_ANY) == 0)
        cca_private->dev_any = TRUE;
    TRACE_DEVEL("dev_any: %d\n", cca_private->dev_any);

    val = getenv(CCA_DEFAULT_DOMAIN_ENVAR);
    if (val != NULL && strcmp(val, CCA_DOMAIN_ANY) == 0)
        cca_private->dom_any = TRUE;
    TRACE_DEVEL("dom_any: %d\n", cca_private->dom_any);
#endif

    /* Get number of adapters, current adapter serial number */
    memcpy(rule_array, "STATCRD2", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    verb_data_length = 0;
    dll_CSUACFQ(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &verb_data_length, NULL);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFQ (STATCRD2) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    rule_array[CCA_KEYWORD_SIZE] = '\0';
    if (sscanf((char *)rule_array, "%u", &cca_private->num_adapters) != 1) {
        TRACE_ERROR("Failed to parse STATCRD2 output: number of adapters: %s\n",
                    rule_array);
        return CKR_FUNCTION_FAILED;
    }
    TRACE_DEVEL("num_adapters: %u\n", cca_private->num_adapters);

#if !defined(__s390__)
   /*
    * Short-circuit for all non-s390x platforms. No domains are supported on
    * those platforms, therefore we force a single domain and skip all future
    * tests.
    */
    cca_private->num_usagedoms = 1;
    cca_private->num_domains = 1;
#else
    /* Get number of domains */
    memcpy(rule_array, "DOM-NUMS", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    verb_data_length = sizeof(cca_private->num_domains);
    dll_CSUACFQ(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &verb_data_length, (unsigned char *)&cca_private->num_domains);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFQ (DOM-NUMS) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }
    cca_private->num_domains = be32toh(cca_private->num_domains);
    TRACE_DEVEL("num_domains: %u\n", cca_private->num_domains);

    /* Get usage domain mask */
    memcpy(rule_array, "DOM-USAG", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    verb_data_length = sizeof(cca_private->usage_domains);
    dll_CSUACFQ(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &verb_data_length, (unsigned char *)cca_private->usage_domains);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFQ (DOM-USAG) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    for (i = 0; i < cca_private->num_domains &&
                (i + 1) * (unsigned int)sizeof(unsigned short) <=
                                                verb_data_length; i++) {
        cca_private->usage_domains[i] = be32toh(cca_private->usage_domains[i]);
        TRACE_DEVEL("usage_domains[%u] = %u\n", i, cca_private->usage_domains[i]);
    }
    cca_private->num_usagedoms = i;
    TRACE_DEVEL("num_usagedoms: %u\n", cca_private->num_usagedoms);
#endif

    return CKR_OK;
}

static CK_RV cca_check_mks(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned char *new_mkvp;
    CK_RV rc;

    rc = cca_iterate_adapters(tokdata, cca_get_and_check_mkvps, NULL);
    if (rc != CKR_OK)
        return rc;

    TRACE_DEBUG("Expected master key verification patterns (queried):\n");
    if (cca_private->expected_sym_mkvp_set == FALSE) {
        /*
         * If a MK change operation is active, and all APQNs have the new SYM MK
         * already, use the new SYM MKVP as the queried one.
         */
        new_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_SYM, NULL);
        if (new_mkvp &&
            memcmp(cca_private->expected_sym_mkvp, cca_zero_mkvp,
                   CCA_MKVP_LENGTH) == 0) {
            TRACE_DEBUG("%s All APQNs already have the new SYM MK\n",__func__);
            memcpy(cca_private->expected_sym_mkvp, new_mkvp, CCA_MKVP_LENGTH);
        }

        TRACE_DEBUG_DUMP("SYM MKVP:  ", cca_private->expected_sym_mkvp,
                         CCA_MKVP_LENGTH);
    } else {
        TRACE_DEBUG("SYM MKVP:  specified in config\n");
    }
    if (cca_private->expected_aes_mkvp_set == FALSE) {
        /*
         * If a MK change operation is active, and all APQNs have the new AES MK
         * already, use the new AES MKVP as the queried one.
         */
        new_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_AES, NULL);
        if (new_mkvp &&
            memcmp(cca_private->expected_aes_mkvp, cca_zero_mkvp,
                   CCA_MKVP_LENGTH) == 0) {
            TRACE_DEBUG("%s All APQNs already have the new AES MK\n",__func__);
            memcpy(cca_private->expected_aes_mkvp, new_mkvp, CCA_MKVP_LENGTH);
        }

        TRACE_DEBUG_DUMP("AES MKVP:  ", cca_private->expected_aes_mkvp,
                         CCA_MKVP_LENGTH);
    } else {
        TRACE_DEBUG("AES MKVP:  specified in config\n");
    }
    if (cca_private->expected_apka_mkvp_set == FALSE) {
        /*
         * If a MK change operation is active, and all APQNs have the new APKA
         * MK already, use the new APKA MKVP as the queried one.
         */
        new_mkvp = cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_APKA, NULL);
        if (new_mkvp &&
            memcmp(cca_private->expected_apka_mkvp, cca_zero_mkvp,
                   CCA_MKVP_LENGTH) == 0) {
            TRACE_DEBUG("%s All APQNs already have the new APKA MK\n",__func__);
            memcpy(cca_private->expected_apka_mkvp, new_mkvp, CCA_MKVP_LENGTH);
        }

        TRACE_DEBUG_DUMP("APKA MKVP: ", cca_private->expected_apka_mkvp,
                         CCA_MKVP_LENGTH);
    } else {
        TRACE_DEBUG("APKA MKVP: specified in config\n");
    }

    return CKR_OK;
}

static CK_RV cca_parse_hex(const char *str, unsigned char *bin, size_t size)
{
    unsigned int i, val;

    if (strncasecmp(str, "0x", 2) == 0)
        str += 2;
    if (strlen(str) != size * 2)
        return CKR_FUNCTION_FAILED;

    for (i = 0; i < size; i++) {
        if (sscanf(str + (i * 2), "%02x", &val) != 1)
            return CKR_FUNCTION_FAILED;
        bin[i] = val;
    }

    return CKR_OK;
}

static CK_RV cca_config_set_pkey_mode(struct cca_private_data *cca_data,
                                      const char *fname, const char *strval)
{
    if (strcmp(strval, "DISABLED") == 0)
        cca_data->pkey_mode = PKEY_MODE_DISABLED;
#ifndef NO_PKEY
    else if (strcmp(strval, "DEFAULT") == 0)
        cca_data->pkey_mode = PKEY_MODE_DEFAULT;
    else if (strcmp(strval, "ENABLED") == 0)
        cca_data->pkey_mode = PKEY_MODE_ENABLED;
#endif
    else {
        TRACE_ERROR("%s unsupported PKEY mode : '%s'\n", __func__, strval);
        OCK_SYSLOG(LOG_ERR,"%s: Error: unsupported PKEY mode '%s' "
                   "in config file '%s'\n", __func__, strval, fname);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV cca_config_set_aes_key_mode(struct cca_private_data *cca_data,
                                         const char *fname, const char *strval)
{
    if (strcmp(strval, "DATA") == 0)
        cca_data->aes_key_mode = AES_KEY_MODE_DATA;
    else if (strcmp(strval, "CIPHER") == 0)
        cca_data->aes_key_mode = AES_KEY_MODE_CIPHER;
    else {
        TRACE_ERROR("%s unsupported AES key mode : '%s'\n", __func__, strval);
        OCK_SYSLOG(LOG_ERR,"%s: Error: unsupported AES key mode '%s' "
                   "in config file '%s'\n", __func__, strval, fname);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV cca_config_parse_exp_mkvps(char *fname,
                                 struct ConfigStructNode *exp_mkvp_node,
                                 unsigned char *expected_sym_mkvp,
                                 CK_BBOOL *expected_sym_mkvp_set,
                                 unsigned char *expected_aes_mkvp,
                                 CK_BBOOL *expected_aes_mkvp_set,
                                 unsigned char *expected_apka_mkvp,
                                 CK_BBOOL *expected_apka_mkvp_set)
{
    struct ConfigBaseNode *c;
    char *str;
    CK_RV rc = CKR_OK;
    int i;

    confignode_foreach(c, exp_mkvp_node->value, i) {
        TRACE_DEBUG("Config node: '%s' type: %u line: %u\n",
                    c->key, c->type, c->line);

        if (strcasecmp(c->key, CCA_CFG_SYM_MKVP) == 0 &&
            (str = confignode_getstr(c)) != NULL) {

            rc = cca_parse_hex(str, expected_sym_mkvp, CCA_MKVP_LENGTH);
            if (rc != CKR_OK) {
                OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': invalid "
                           "hex value '%s' at line %d\n", fname,
                           confignode_getstr(c), c->line);
                TRACE_ERROR("Error parsing config file '%s': invalid hex value "
                            "'%s' at line %d\n", fname, confignode_getstr(c),
                            c->line);
                break;
            }

            *expected_sym_mkvp_set = TRUE;
            continue;
        }

        if (strcasecmp(c->key, CCA_CFG_AES_MKVP) == 0 &&
            (str = confignode_getstr(c)) != NULL) {

            rc = cca_parse_hex(str, expected_aes_mkvp, CCA_MKVP_LENGTH);
            if (rc != CKR_OK) {
                OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': invalid "
                           "hex value '%s' at line %d\n", fname,
                           confignode_getstr(c), c->line);
                TRACE_ERROR("Error parsing config file '%s': invalid hex value "
                            "'%s' at line %d\n", fname, confignode_getstr(c),
                            c->line);
                break;
            }

            *expected_aes_mkvp_set = TRUE;
            continue;
        }

        if (strcasecmp(c->key, CCA_CFG_APKA_MKVP) == 0 &&
            (str = confignode_getstr(c)) != NULL) {

            rc = cca_parse_hex(str, expected_apka_mkvp, CCA_MKVP_LENGTH);
            if (rc != CKR_OK) {
                OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': invalid "
                           "hex value '%s' at line %d\n", fname,
                           confignode_getstr(c), c->line);
                TRACE_ERROR("Error parsing config file '%s': invalid hex value "
                            "'%s' at line %d\n", fname, confignode_getstr(c),
                            c->line);
                break;
            }

            *expected_apka_mkvp_set = TRUE;
            continue;
        }

        OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': unexpected token "
                   "'%s' at line %d\n", fname, c->key, c->line);
        TRACE_ERROR("Error parsing config file '%s': unexpected token '%s' "
                    "at line %d\n", fname, c->key, c->line);
        return CKR_FUNCTION_FAILED;
    }

    TRACE_DEBUG("Expected master key verification patterns\n");
    if (*expected_sym_mkvp_set == TRUE) {
        TRACE_DEBUG_DUMP("SYM MKVP:  ", expected_sym_mkvp, CCA_MKVP_LENGTH);
    } else {
        TRACE_DEBUG("SYM MKVP:  not specified\n");
    }
    if (*expected_aes_mkvp_set == TRUE) {
        TRACE_DEBUG_DUMP("AES MKVP:  ", expected_aes_mkvp, CCA_MKVP_LENGTH);
    } else {
        TRACE_DEBUG("AES MKVP:  not specified\n");
    }
    if (*expected_apka_mkvp_set == TRUE) {
        TRACE_DEBUG_DUMP("APKA MKVP: ", expected_apka_mkvp, CCA_MKVP_LENGTH);
    } else {
        TRACE_DEBUG("APKA MKVP: not specified\n");
    }

    return rc;
}

void cca_config_parse_error(int line, int col, const char *msg)
{
    OCK_SYSLOG(LOG_ERR, "Error parsing config file: line %d column %d: %s\n",
               line, col, msg);
    TRACE_ERROR("Error parsing config file: line %d column %d: %s\n", line, col,
                msg);
}

CK_RV cca_load_config_file(STDLL_TokData_t *tokdata, char *conf_name)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    char fname[PATH_MAX];
    FILE *file;
    struct ConfigBaseNode *c, *config = NULL;
    struct ConfigStructNode *struct_node;
    CK_RV rc = CKR_OK;
    int ret, i;
    const char *strval;

    if (conf_name == NULL || strlen(conf_name) == 0)
        return CKR_OK;

    if (conf_name[0] == '/') {
        /* Absolute path name */
        strncpy(fname, conf_name, sizeof(fname) - 1);
        fname[sizeof(fname) - 1] = '\0';
    } else {
        /* relative path name */
        snprintf(fname, sizeof(fname), "%s/%s", OCK_CONFDIR, conf_name);
        fname[sizeof(fname) - 1] = '\0';
    }

    file = fopen(fname, "r");
    if (file == NULL) {
        TRACE_ERROR("%s fopen('%s') failed with errno: %s\n", __func__, fname,
                    strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    ret = parse_configlib_file(file, &config, cca_config_parse_error, 0);
    if (ret != 0) {
        TRACE_ERROR("Error parsing config file '%s'\n", fname);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    strncpy(cca_private->token_config_filename, fname,
            sizeof(cca_private->token_config_filename));
    cca_private->token_config_filename[
                    sizeof(cca_private->token_config_filename) - 1] = '\0';

#ifndef NO_PKEY
    cca_private->pkey_mode = PKEY_MODE_DEFAULT;
#else
    cca_private->pkey_mode = PKEY_MODE_DISABLED;
#endif

    cca_private->aes_key_mode = AES_KEY_MODE_DATA;

    confignode_foreach(c, config, i) {
        TRACE_DEBUG("Config node: '%s' type: %u line: %u\n",
                    c->key, c->type, c->line);

        if (confignode_hastype(c, CT_FILEVERSION)) {
            TRACE_DEBUG("Config file version: '%s'\n",
                        confignode_to_fileversion(c)->base.key);
            continue;
        }

        if (confignode_hastype(c, CT_BARECONST)) {
            /* single keyword tokens */
            if (strcasecmp(c->key, "FORCE_SENSITIVE") == 0) {
                cca_private->cka_sensitive_default_true = TRUE;
                continue;
            }
        }

        if (confignode_hastype(c, CT_BAREVAL)) {
            /* New style (key = value) tokens */
            strval = confignode_getstr(c);

            if (strcasecmp(c->key, "PKEY_MODE") == 0) {
                rc = cca_config_set_pkey_mode(cca_private, fname, strval);
                if (rc != CKR_OK)
                    break;
                continue;
            }

            if (strcasecmp(c->key, "AES_KEY_MODE") == 0) {
                rc = cca_config_set_aes_key_mode(cca_private, fname, strval);
                if (rc != CKR_OK)
                    break;
                continue;
            }
        }

        if (confignode_hastype(c, CT_STRUCT)) {
            struct_node = confignode_to_struct(c);
            if (strcasecmp(struct_node->base.key, CCA_CFG_EXPECTED_MKVPS) == 0) {
                rc = cca_config_parse_exp_mkvps(fname, struct_node,
                                        cca_private->expected_sym_mkvp,
                                        &cca_private->expected_sym_mkvp_set,
                                        cca_private->expected_aes_mkvp,
                                        &cca_private->expected_aes_mkvp_set,
                                        cca_private->expected_apka_mkvp,
                                        &cca_private->expected_apka_mkvp_set);
                if (rc != CKR_OK)
                    break;
                continue;
            }

            OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': unexpected "
                       "token '%s' at line %d\n", fname, c->key, c->line);
            TRACE_ERROR("Error parsing config file '%s': unexpected token '%s' "
                        "at line %d\n", fname, c->key, c->line);
            rc = CKR_FUNCTION_FAILED;
            break;
        }

        OCK_SYSLOG(LOG_ERR, "Error parsing config file '%s': unexpected token "
                   "'%s' at line %d\n", fname, c->key, c->line);
        TRACE_ERROR("Error parsing config file '%s': unexpected token '%s' "
                    "at line %d\n", fname, c->key, c->line);
        rc = CKR_FUNCTION_FAILED;
        break;
    }

done:
    confignode_deepfree(config);
    fclose(file);

    return rc;
}

#ifndef NO_PKEY
static CK_RV ccatok_pkey_add_attr_to_rule_array(CK_ATTRIBUTE_TYPE type,
                                                CK_BYTE *rule_array,
                                                CK_ULONG rule_array_size,
                                                CK_ULONG *rule_array_count)
{
    if ((*rule_array_count + 1) * CCA_KEYWORD_SIZE > rule_array_size)
        return CKR_BUFFER_TOO_SMALL;

    switch (type) {
    case CKA_IBM_PROTKEY_EXTRACTABLE:
        memcpy(rule_array + (*rule_array_count * CCA_KEYWORD_SIZE),
               "XPRTCPAC", CCA_KEYWORD_SIZE);
        (*rule_array_count)++;
        break;
    default:
        break;
    }

    return CKR_OK;
}

/*
 * This routine checks if a given attr is applicable to pass it to the CCA
 * host lib via its corresponding rule_array keyword.
 */
static CK_BBOOL ccatok_pkey_attr_applicable(STDLL_TokData_t *tokdata,
                                            CK_ATTRIBUTE *attr,
                                            CK_KEY_TYPE ktype,
                                            int curve_type, int curve_bitlen,
                                            CK_IBM_CCA_AES_KEY_MODE_TYPE
                                                                aes_key_mode)
{
    struct cca_private_data *cca_data = tokdata->private_data;

    /*
     * On older cards, CKA_IBM_PROTKEY_EXTRACTABLE might cause errors, so
     * filter it out when the PKEY option is not supported on this system.
     */
    if (attr->type == CKA_IBM_PROTKEY_EXTRACTABLE &&
        cca_data->pkey_wrap_supported == 0)
        return CK_FALSE;

    switch (ktype) {
    case CKK_AES:
    case CKK_AES_XTS:
        /*
         * CCA AES DATA keys don't support any pkey attributes to be set, but
         * AES CIPHER keys do support the XPRTCPAC keyword to allow export to
         * CPACF protected key format.
         */
        if (aes_key_mode != CK_IBM_CCA_AES_CIPHER_KEY)
            return CK_FALSE;
        switch (attr->type) {
        case CKA_IBM_PROTKEY_EXTRACTABLE:
            return *(CK_BBOOL *)attr->pValue;
        }
        break;
    case CKK_EC:
        /*
         * There is currently only one attribute with a corresponding rule
         * array keyword.
         */
        switch (attr->type) {
        case CKA_IBM_PROTKEY_EXTRACTABLE:
            if ((*(CK_BBOOL *)attr->pValue) == CK_TRUE) {
                /*
                 * From CCA 7.3 Application Programmer's Guide, table 282:
                 * Allow export to CPACF protected key format. Valid for ECC
                 * curves P256, P384, P521, Ed25519, and Ed448.
                 */
                switch (curve_type) {
                case PRIME_CURVE:
                    if (curve_bitlen == 256 || curve_bitlen == 384 ||
                        curve_bitlen == 521)
                        return CK_TRUE;
                    break;
                case EDWARDS_CURVE:
                    if (curve_bitlen == 255 || curve_bitlen == 448)
                        return CK_TRUE;
                    break;
                default:
                    break;
                }
            }
        }
        break;
    default:
        /*
         * Any other key types (RSA, ...) are currently not handled. No
         * additional rule array keywords here.
         */
        break;
    }

    return CK_FALSE;
}

/*
 * Add protected key related attributes to be passed to CCA via the rule_array.
 */
static CK_RV ccatok_pkey_add_attrs(STDLL_TokData_t * tokdata, TEMPLATE *template,
                            CK_KEY_TYPE ktype, int curve_type, int curve_bitlen,
                            CK_IBM_CCA_AES_KEY_MODE_TYPE aes_key_mode,
                            CK_BYTE *rule_array, CK_ULONG rule_array_size,
                            CK_ULONG *rule_array_count)
{
    DL_NODE *node;
    CK_ATTRIBUTE_PTR attr;
    CK_RV ret;

    node = template->attribute_list;
    while (node != NULL) {
        attr = node->data;

        if (ccatok_pkey_attr_applicable(tokdata, attr, ktype,
                                        curve_type, curve_bitlen,
                                        aes_key_mode)) {
            ret = ccatok_pkey_add_attr_to_rule_array(attr->type, rule_array,
                                         rule_array_size, rule_array_count);
            if (ret != CKR_OK)
                return ret;
        }

        node = node->next;
    }

    return CKR_OK;
}

#define MAXECPROTKEYSIZE           112 /* max 80 + 32 bytes for p521 */
#define PKEYDEVICE                 "/dev/pkey"

typedef struct {
    STDLL_TokData_t *tokdata;
    CK_BBOOL wrap_was_successful;
    CK_RV wrap_error;
    CK_VOID_PTR secure_key;
    CK_ULONG secure_key_len;
    CK_BYTE *pkey_buf;
    size_t *pkey_buflen_p;
    enum cca_token_type keytype;
    /* for AES XTS processing */
    CK_VOID_PTR secure_key2;
    CK_ULONG secure_key_len2;
    CK_BYTE *pkey_buf2;
    size_t *pkey_buflen_p2;
    CK_BBOOL aes_xts;
} pkey_wrap_handler_data_t;

/*
 * On older kernels, the PKEY_KBLOB2PROTK3 ioctl is not yet available, which is
 * no problem at runtime: protected key support is then just not available.
 * But we want that the CCA token still builds on such systems, so let's copy
 * the missing #defines and structs from kernel asm/pkey.h
 */
#ifndef PKEY_KBLOB2PROTK3

struct pkey_kblob2pkey3 {
    __u8 *key;       /* in: pointer to key blob        */
    __u32 keylen;            /* in: key blob size          */
    struct pkey_apqn *apqns; /* in: ptr to list of apqn targets */
    __u32 apqn_entries;      /* in: # of apqn target list entries  */
    __u32 pkeytype;     /* out: prot key type (enum pkey_key_type) */
    __u32 pkeylen;   /* in/out: size of pkey buffer/actual len of pkey */
    __u8 *pkey;      /* in: pkey blob buffer space ptr */
};
#define PKEY_KBLOB2PROTK3 _IOWR(PKEY_IOCTL_MAGIC, 0x1D, struct pkey_kblob2pkey3)

#define PKEY_TYPE_CCA_ECC    (__u32)0x1f

#endif /* PKEY_KBLOB2PROTK3 */

static enum pkey_key_type ccatok_pkey_type_from_keytype(enum cca_token_type keytype)
{
    switch (keytype) {
    case sec_aes_data_key:
        return PKEY_TYPE_CCA_DATA;
    case sec_aes_cipher_key:
        return PKEY_TYPE_CCA_CIPHER;
    case sec_ecc_priv_key:
        return PKEY_TYPE_CCA_ECC;
    default:
        break;
    }

    return 0;
}

/*
 * Callback function used by ccatok_pkey_skey2pkey() for creating a protected
 * key using (card,domain) via the PKEY_KBLOB2PROTK3 ioctl.
 * Note that the PKEY_KBLOB2PROTK3 ioctl requires kernel 5.10 or later.
 * On older kernels this function fails when called at token init, trying to
 * determine the wkvp from the firmware wrapping key. In this case, protected
 * key support for CCA is just not available (indicated in cca_private_data).
 */
static CK_RV ccatok_pkey_sec2prot(STDLL_TokData_t *tokdata, const char *adapter,
                                  unsigned short card, unsigned short domain,
                                  void *handler_data)
{
    pkey_wrap_handler_data_t *data = (pkey_wrap_handler_data_t *) handler_data;
    struct cca_private_data *cca_data = data->tokdata->private_data;
    struct pkey_kblob2pkey3 io;
    struct pkey_apqn apqn;
    int rc, i;

    UNUSED(tokdata);
    UNUSED(adapter);

    if (data->wrap_was_successful)
        goto done;

    apqn.card = card;
    apqn.domain = domain;

    memset(&io, 0, sizeof(io));
    io.key = data->secure_key;
    io.keylen = data->secure_key_len;
    io.apqns = &apqn;
    io.apqn_entries = 1;
    io.pkeytype = ccatok_pkey_type_from_keytype(data->keytype);
    io.pkeylen = *(data->pkey_buflen_p);
    io.pkey = data->pkey_buf;

    for (i = 0; i < 10; i++) {
        rc = ioctl(cca_data->pkeyfd, PKEY_KBLOB2PROTK3, &io);
        if (rc == 0 || (errno != -EBUSY && errno != -EAGAIN))
            break;
        sleep(1);
    }
    if (rc != 0) {
        data->wrap_error = CKR_FUNCTION_FAILED;
        data->wrap_was_successful = CK_FALSE;
        goto done;
    }
    *(data->pkey_buflen_p) = io.pkeylen;
    if (data->aes_xts) {
        memset(&io, 0, sizeof(io));
        io.key = data->secure_key2;
        io.keylen = data->secure_key_len2;
        io.apqns = &apqn;
        io.apqn_entries = 1;
        io.pkeytype = ccatok_pkey_type_from_keytype(data->keytype);
        io.pkeylen = *(data->pkey_buflen_p2);
        io.pkey = data->pkey_buf2;
        for (i = 0; i < 10; i++) {
            rc = ioctl(cca_data->pkeyfd, PKEY_KBLOB2PROTK3, &io);
            if (rc == 0 || (errno != -EBUSY && errno != -EAGAIN))
                break;
            sleep(1);
        }
        if (rc != 0) {
            data->wrap_error = CKR_FUNCTION_FAILED;
            data->wrap_was_successful = CK_FALSE;
            goto done;
        }
        *(data->pkey_buflen_p2) = io.pkeylen;
    }
    data->wrap_error = CKR_OK;
    data->wrap_was_successful = CK_TRUE;

done:

    /*
     * Always return ok, calling function loops over this handler until
     * data->wrap_was_successful = true, or no more APQN left.
     * Pass back error in handler data anyway.
     */
    return CKR_OK;
}

/*
 * Creates a protected key from the given secure key object by iterating
 * over all APQNs.
 */
static CK_RV ccatok_pkey_skey2pkey(STDLL_TokData_t *tokdata,
                                   CK_ATTRIBUTE *skey_attr,
                                   CK_ATTRIBUTE **pkey_attr, CK_BBOOL aes_xts)
{
    CK_ATTRIBUTE *tmp_attr = NULL;
    CK_BYTE pkey_buf[MAXECPROTKEYSIZE], pkey_buf2[MAXECPROTKEYSIZE],
            pkey_buffer[MAXECPROTKEYSIZE * 2];
    CK_ULONG pkey_buflen = sizeof(pkey_buf);
    CK_ULONG pkey_buflen2 = sizeof(pkey_buf2);
    pkey_wrap_handler_data_t pkey_wrap_handler_data;
    CK_RV ret;
    enum cca_token_type key_type;
    unsigned int token_keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;
    unsigned int num_retries = 0;

    /* Determine CCA key type */
    if (analyse_cca_key_token(skey_attr->pValue, (aes_xts ?
                              skey_attr->ulValueLen / 2 :
                              skey_attr->ulValueLen), &key_type,
                              &token_keybitsize, &mkvp) != TRUE) {
       TRACE_ERROR("Invalid/unknown cca token, cannot get key type\n");
       ret = CKR_FUNCTION_FAILED;
       goto done;
    }

    if (check_expected_mkvp(tokdata, key_type, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        ret = CKR_DEVICE_ERROR;
        goto done;
    }

    /* Create the protected key by iterating over all APQNs */
    memset(&pkey_wrap_handler_data, 0, sizeof(pkey_wrap_handler_data_t));
    pkey_wrap_handler_data.tokdata = tokdata;
    pkey_wrap_handler_data.secure_key = skey_attr->pValue;
    pkey_wrap_handler_data.secure_key_len = (aes_xts ? skey_attr->ulValueLen / 2
                                                     : skey_attr->ulValueLen);
    pkey_wrap_handler_data.pkey_buf = (CK_BYTE *)&pkey_buf;
    pkey_wrap_handler_data.pkey_buflen_p = &pkey_buflen;
    pkey_wrap_handler_data.aes_xts = aes_xts;

    if (aes_xts) {
        if (analyse_cca_key_token((CK_BYTE *)skey_attr->pValue + skey_attr->ulValueLen / 2,
                                  skey_attr->ulValueLen / 2,
                                  &key_type, &token_keybitsize,
                                  &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token, cannot get key type\n");
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (check_expected_mkvp(tokdata, key_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            ret = CKR_DEVICE_ERROR;
            goto done;
        }

        pkey_wrap_handler_data.secure_key2 = (CK_BYTE *)skey_attr->pValue +
                                             skey_attr->ulValueLen / 2;
        pkey_wrap_handler_data.secure_key_len2 = skey_attr->ulValueLen / 2;
        pkey_wrap_handler_data.pkey_buf2 = (CK_BYTE *)&pkey_buf2;
        pkey_wrap_handler_data.pkey_buflen_p2 = &pkey_buflen2;
        pkey_wrap_handler_data.keytype = key_type;
    }

    while (num_retries < 3600) {
        ret = cca_iterate_adapters(tokdata, ccatok_pkey_sec2prot,
                                   &pkey_wrap_handler_data);
        if (ret == CKR_OK && pkey_wrap_handler_data.wrap_was_successful)
            break;

        /* Retry the op if key encrypted with new MK and an MK change is active */
        if (new_mk == CK_TRUE &&
            cca_mk_change_find_op_by_keytype(tokdata, key_type) != NULL) {
            sleep(1);
            num_retries++;
            continue;
        }
        break;
    }

    if (ret != CKR_OK || !pkey_wrap_handler_data.wrap_was_successful) {
        TRACE_ERROR("cca_iterate_adapters failed or no APQN could create the pkey.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Build new attribute for protected key */
    if (aes_xts) {
        memcpy(pkey_buffer, pkey_buf, pkey_buflen);
        memcpy(pkey_buffer + pkey_buflen, pkey_buf2, pkey_buflen2);
        ret = build_attribute(CKA_IBM_OPAQUE_PKEY, pkey_buffer,
                              pkey_buflen + pkey_buflen2, &tmp_attr);
        if (ret != CKR_OK) {
            TRACE_ERROR("build_attribute failed with rc=0x%lx\n", ret);
            ret = CKR_FUNCTION_FAILED;;
            goto done;
        }
    } else {
        ret = build_attribute(CKA_IBM_OPAQUE_PKEY, pkey_buf, pkey_buflen,
                              &tmp_attr);
        if (ret != CKR_OK) {
            TRACE_ERROR("build_attribute failed with rc=0x%lx\n", ret);
            ret = CKR_FUNCTION_FAILED;;
            goto done;
        }
    }
    ret = CKR_OK;

done:

    *pkey_attr = tmp_attr;

    return ret;
}

/*
 * Save the current firmware wrapping key verification pattern in the tokdata:
 * create a dummy test key, transform it into a protected key, and store the wk
 * verification pattern in the tokdata.
 */
static CK_RV ccatok_pkey_get_firmware_wkvp(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ATTRIBUTE *pkey_attr = NULL, *sec_attr = NULL;
    CK_RV ret;
    long return_code = 0, reason_code = 0;
    long exit_data_len = 0, clear_key_bit_length = 0;
    unsigned char exit_data[4];
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
    long rule_array_count;
    unsigned char *clear_key_value = NULL;
    long key_name_length = 0;
    unsigned char key_name[CCA_KEY_ID_SIZE] = { 0, };
    long user_data_length = 0;
    unsigned char user_data[64] = { 0, };
    long token_data_length = 0;
    long verb_data_length = 0;
    unsigned char verb_data[64] = { 0, };
    unsigned char the_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    long the_key_token_length = sizeof(the_key_token);
    unsigned char key_type_1[8] = { ' ', };
    unsigned char key_type_2[8] = { ' ', };
    long key_name_1_length = 0;
    long key_name_2_length = 0;
    long user_data_1_length = 0;
    long user_data_2_length = 0;
    long kek_identifier_1_length = 0;
    long kek_identifier_2_length = 0;
    long the_2nd_key_token_length = 0;
    unsigned int min_card_version;

    /* Check CCA host library version: XPRTCPAC requires min 7.0.0 */
    if (cca_data->cca_lib_version.ver < 7) {
        TRACE_WARNING("CCA host lib is %d.%d.%d, but pkey support requires min 7.0.0\n",
                    cca_data->cca_lib_version.ver,cca_data->cca_lib_version.rel,
                    cca_data->cca_lib_version.mod);
        OCK_SYSLOG(LOG_WARNING, "CCA host lib is %d.%d.%d, but pkey support requires min 7.0.0\n",
                   cca_data->cca_lib_version.ver,cca_data->cca_lib_version.rel,
                   cca_data->cca_lib_version.mod);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    /* Read min card version from CCA private data. Needs a read lock. */
    if (pthread_rwlock_rdlock(&cca_data->min_card_version_rwlock) != 0) {
        TRACE_ERROR("CCA min_card_version RD-Lock failed.\n");
        return CKR_CANT_LOCK;
    }
    min_card_version = cca_data->min_card_version.ver;
    if (pthread_rwlock_unlock(&cca_data->min_card_version_rwlock) != 0) {
        TRACE_ERROR("CCA min_card_version RD-Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    /* Check minimum card version, XPRTCPAC requires min CEX7C */
    if (min_card_version < 7) {
        TRACE_WARNING("Minimum card version must be CEX7C, but we only have %d.%d.%d\n",
                    cca_data->min_card_version.ver,cca_data->min_card_version.rel,
                    cca_data->min_card_version.mod);
        OCK_SYSLOG(LOG_WARNING, "Minimum card version must be CEX7C, but we only have %d.%d.%d\n",
                   cca_data->min_card_version.ver,cca_data->min_card_version.rel,
                   cca_data->min_card_version.mod);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    /* Build CPACF-exportable AES internal cipher key token */
    rule_array_count = 5;
    memcpy(rule_array, "INTERNAL" "NO-KEY  " "AES     " "CIPHER  " "XPRTCPAC",
           rule_array_count * CCA_KEYWORD_SIZE);

    dll_CSNBKTB2(&return_code, &reason_code, &exit_data_len, exit_data,
                 &rule_array_count, rule_array, &clear_key_bit_length,
                 clear_key_value, &key_name_length, key_name, &user_data_length,
                 user_data, &token_data_length, NULL, &verb_data_length,
                 verb_data, &the_key_token_length, the_key_token);

    if (return_code != 0) {
        TRACE_ERROR("CSNBTKB2 (TOKEN BUILD2) failed with %ld/%ld\n",
            return_code, reason_code);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Generate the key */
    memset(rule_array, 0, sizeof(rule_array));
    memcpy(rule_array, "AES     " "OP      ", 2 * CCA_KEYWORD_SIZE);
    rule_array_count = 2;
    clear_key_bit_length = 256;
    memcpy(key_type_1, "TOKEN   ", CCA_KEYWORD_SIZE);
    the_key_token_length = sizeof(the_key_token);

    dll_CSNBKGN2(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                 rule_array, &clear_key_bit_length, key_type_1, key_type_2,
                 &key_name_1_length, NULL, &key_name_2_length, NULL,
                 &user_data_1_length, NULL, &user_data_2_length, NULL,
                 &kek_identifier_1_length, NULL, &kek_identifier_2_length,
                 NULL, &the_key_token_length, the_key_token,
                 &the_2nd_key_token_length, NULL);

    if (return_code != 0) {
        TRACE_ERROR("CSNBKGN2(KEYGEN2) failed with %ld/%ld\n",
            return_code, reason_code);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Build attribute for secure key token */
    ret = build_attribute(CKA_IBM_OPAQUE, (CK_BYTE *)&the_key_token,
                          the_key_token_length, &sec_attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("build_attribute CKA_IBM_OPAQUE failed with ret=0x%lx\n", ret);
        goto done;
    }

    /*
     * Create a protected key from this token to obtain the firmware wkvp. When
     * this function returns ok, we have a 64 byte pkey value: 32 bytes
     * encrypted key + 32 bytes vp.
     */
    ret = ccatok_pkey_skey2pkey(tokdata, sec_attr, &pkey_attr, FALSE);
    if (ret != CKR_OK) {
        TRACE_ERROR("ccatok_pkey_skey2pkey failed with ret=0x%lx\n", ret);
        goto done;
    }

    /* Save WKVP in token data */
    if (pthread_rwlock_wrlock(&cca_data->pkey_rwlock)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        ret = CKR_CANT_LOCK;
        goto done;
    }

    memcpy(&cca_data->pkey_mk_vp, (CK_BYTE *)pkey_attr->pValue + AES_KEY_SIZE_256,
           PKEY_MK_VP_LENGTH);

    __sync_or_and_fetch(&cca_data->pkey_wrap_supported, 1);

    if (pthread_rwlock_unlock(&cca_data->pkey_rwlock)) {
        TRACE_ERROR("%s Failed to unlock pkey lock\n", __func__);
    }

done:

    if (sec_attr)
        free(sec_attr);
    if (pkey_attr)
        free(pkey_attr);

    return ret;
}

/*
 * Return true if PKEY_MODE DISABLED is set in the token specific
 * config file, false otherwise.
 */
static CK_BBOOL ccatok_pkey_option_disabled(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_data = tokdata->private_data;

    if (cca_data->pkey_mode == PKEY_MODE_DISABLED)
        return CK_TRUE;

    return CK_FALSE;
}

/**
 * Return true, if the given key obj has a valid protected key, i.e. its
 * verification pattern matches the one of the current master key.
 */
static CK_BBOOL ccatok_pkey_is_valid(STDLL_TokData_t *tokdata, OBJECT *key_obj)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ATTRIBUTE *pkey_attr = NULL;
    int vp_offset;
    CK_BBOOL ret = CK_FALSE;

    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE_PKEY,
                                         &pkey_attr) == CKR_OK) {
        if (pkey_attr->ulValueLen >= AES_KEY_SIZE_128 + PKEY_MK_VP_LENGTH) {
            vp_offset = pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH;
            if (pthread_rwlock_rdlock(&cca_data->pkey_rwlock)) {
                TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
                goto done;
            }
            if (memcmp((CK_BYTE *)pkey_attr->pValue + vp_offset,
                       &cca_data->pkey_mk_vp,
                       PKEY_MK_VP_LENGTH) == 0) {
                ret = CK_TRUE;
            }
            if (pthread_rwlock_unlock(&cca_data->pkey_rwlock)) {
                TRACE_ERROR("%s Failed to unlock pkey lock\n", __func__);
            }
        }
    }

done:
    return ret;
}

/**
 * Create a new protected key for the given key obj and update attribute
 * CKA_IBM_OPAQUE with the new pkey.
 */
static CK_RV ccatok_pkey_update(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                                CK_BBOOL aes_xts)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ATTRIBUTE *skey_attr = NULL;
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_RV ret;
    int vp_offset;
    int num_retries = 0;

    /* Get secure key from obj */
    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                         &skey_attr) != CKR_OK) {
        TRACE_ERROR("This key has no blob: should not occur!\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

retry:
    /* Transform the secure key into a protected key */
    ret = ccatok_pkey_skey2pkey(tokdata, skey_attr, &pkey_attr, aes_xts);
    if (ret != CKR_OK) {
        TRACE_ERROR("protected key creation failed with rc=0x%lx\n",ret);
        goto done;
    }

    if (pthread_rwlock_rdlock(&cca_data->pkey_rwlock)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        ret = CKR_CANT_LOCK;
        goto done;
    }

    /*
     * Check if the new pkey's verification pattern matches the one in
     * cca_data. This should always be the case, except there was a live
     * guest relocation (LGR) in the middle of the process.
     */
    vp_offset = pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH;
    if (memcmp(&cca_data->pkey_mk_vp, (CK_BYTE *)pkey_attr->pValue + vp_offset,
               PKEY_MK_VP_LENGTH) != 0) {
        TRACE_ERROR("vp of this pkey does not match with the one in cca_data\n");
        ret = CKR_FUNCTION_FAILED;
    }

    if (aes_xts) {
        /*
         * Check if the new pkey's verification pattern matches the one in
         * cca_data. This should always be the case, except there was a live
         * guest relocation (LGR) in the middle of the process.
         * AES XTS has two keys, two keys are concatenated.
         * Second key is checked above and the first key is checked here
         */
        vp_offset = pkey_attr->ulValueLen / 2 - PKEY_MK_VP_LENGTH;
        if (memcmp(&cca_data->pkey_mk_vp, (CK_BYTE *)pkey_attr->pValue + vp_offset,
                   PKEY_MK_VP_LENGTH) != 0) {
            TRACE_ERROR("vp of this pkey does not match with the one in cca_data\n");
            ret = CKR_FUNCTION_FAILED;
        }
    }

    if (pthread_rwlock_unlock(&cca_data->pkey_rwlock)) {
        TRACE_ERROR("%s Failed to unlock pkey lock\n", __func__);
    }

    if (ret != CKR_OK)  {
        /*
         * Verification pattern does not match. Create it again and retry.
         * If there was an LGR, this op now takes place on the new system
         * and should succeed.
         */
        ret = ccatok_pkey_get_firmware_wkvp(tokdata);
        if (ret != CKR_OK)
            goto done;

        num_retries++;
        if (num_retries < PKEY_CONVERT_KEY_RETRIES) {
            if (pkey_attr != NULL)
                free(pkey_attr);
            TRACE_DEVEL("%s VP mismatch probably due to LGR, retry %d of %d ...\n",
                        __func__, num_retries, PKEY_CONVERT_KEY_RETRIES);
            goto retry;
        }
    }

    if (ret != CKR_OK)
        goto done;

    /*
     * Now update the key obj. If it's a token obj, it will be also updated
     * in the repository.
     */
    ret = pkey_update_and_save(tokdata, key_obj, &pkey_attr);
    if (ret != CKR_OK) {
        TRACE_ERROR("pkey_update_and_save failed with rc=0x%lx\n", ret);
        goto done;
    }

    ret = CKR_OK;

done:
    if (pkey_attr != NULL)
        free(pkey_attr);

    return ret;
}

/**
 * Returns true if the session is ok for creating protected keys, false
 * otherwise. The session must be read/write for token objects, and not public
 * nor SO for private objects.
 */
static CK_BBOOL ccatok_pkey_session_ok_for_obj(SESSION *session,
                                               OBJECT *key_obj)
{
    if (object_is_token_object(key_obj) &&
        (session->session_info.flags & CKF_RW_SESSION) == 0)
        return CK_FALSE;

    if (object_is_private(key_obj)) {
        switch (session->session_info.state) {
        case CKS_RO_PUBLIC_SESSION:
        case CKS_RW_PUBLIC_SESSION:
        case CKS_RW_SO_FUNCTIONS:
            return CK_FALSE;
        default:
            break;
        }
    }

    return CK_TRUE;
}

/**
 * Checks if the preconditions for using the related protected key of
 * the given secure key object are met. The caller of this routine must
 * have a READ_LOCK on the key object.
 *
 * The routine internally creates a protected key and adds it to the key_obj,
 * if the machine supports pkeys, the key is eligible for pkey support, does
 * not already have a valid pkey, and other conditions, like r/w session, are
 * fulfilled. As adding a protected key to the key_obj involves unlocking and
 * re-locking, the key blob, or any other attribute of the key, that was
 * retrieved via h_opaque_2_blob before calling this function might be no more
 * valid in a parallel environment.
 *
 * Therefore, the following return codes tell the calling function how to
 * proceed:
 *
 * @return CKR_OK:
 *            a protected key was possibly created successfully and everything
 *            is fine to use pkey support. In this case the protected key
 *            shall be used, but a previously obtained key blob or other attr
 *            might be invalid, because of a possible unlock/re-lock of the
 *            key_obj.
 *
 *         CKR_FUNCTION_NOT_SUPPORTED:
 *            The system, session or key do not allow to use pkey support, but
 *            no attempt was made to create a protected key. So the key blob,
 *            or any other attr, is still valid and a fallback into the ep11
 *            path is ok.
 *
 *         all others:
 *            An internal error occurred and it was possibly attempted to create
 *            a protected key for the object. In this case, the key blob, or
 *            any other attr, might be no longer valid in a parallel environment
 *            and the ep11 fallback is not possible anymore. The calling
 *            function shall return with an error in this case.
 */
static CK_RV ccatok_pkey_check(STDLL_TokData_t *tokdata, SESSION *session,
                               OBJECT *key_obj, CK_MECHANISM *mech)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;

    /* Check if CPACF supports the operation implied by this key and mech */
    if (!pkey_op_supported_by_cpacf(cca_data->msa_level, mech->mechanism,
                                    key_obj->template)) {
        goto done;
    }

    /* Check config option */
    switch (cca_data->pkey_mode) {
    case PKEY_MODE_DISABLED:
        goto done;
        break;
    case PKEY_MODE_DEFAULT:
    case PKEY_MODE_ENABLED:
        /*
         * Use existing pkeys, re-create invalid pkeys, and also create new
         * pkeys for secret/private keys that do not already have one. EC
         * public keys that are pkey-extractable, can always be used via CPACF
         * as there is no protected key involved.
         */
        if (pkey_is_ec_public_key(key_obj->template) &&
            object_is_pkey_extractable(key_obj)) {
            ret = CKR_OK;
            goto done;
        }

        if (!object_is_pkey_extractable(key_obj) ||
            !cca_data->pkey_wrap_supported) {
            goto done;
        }
        if (template_attribute_get_non_empty(key_obj->template,
                                             CKA_IBM_OPAQUE_PKEY,
                                             &opaque_attr) != CKR_OK ||
            !ccatok_pkey_is_valid(tokdata, key_obj)) {
            /*
             * this key has either no pkey attr, or it is not valid,
             * try to create one, if the session state allows it.
             */
            if (!ccatok_pkey_session_ok_for_obj(session, key_obj))
                goto done;

            ret = ccatok_pkey_update(tokdata, key_obj,
                                     mech->mechanism == CKM_AES_XTS);
            if (ret != CKR_OK) {
                TRACE_ERROR("error updating the protected key, rc=0x%lx\n", ret);
                if (ret == CKR_FUNCTION_NOT_SUPPORTED)
                    ret = CKR_FUNCTION_FAILED;
                goto done;
            }
        }
        break;
    default:
        /* should not occur */
        TRACE_ERROR("PKEY_MODE %i unsupported.\n", cca_data->pkey_mode);
        ret = CKR_FUNCTION_FAILED;
        goto done;
        break;
    }

    ret = CKR_OK;

done:

    return ret;
}

static CK_RV ccatok_pkey_convert_key(STDLL_TokData_t *tokdata, SESSION *session,
                                     OBJECT *key_obj, CK_BBOOL xts_mode,
                                     CK_BYTE *protkey, CK_ULONG *protkey_len)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    int num_retries = 0, vp_offset1, vp_offset2;
    CK_ATTRIBUTE *skey_attr = NULL;
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_RV rc, rc2;

    /* Try to obtain a write lock on the key_obj */
    rc = object_unlock(key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("object_unlock failed, rc=0x%lx\n", rc);
        goto done;
    }

    rc = object_lock(key_obj, WRITE_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not obtain write lock.\n");
        goto done;
    }

    /*
     * The key_obj could be modified between unlock and lock. Therefore get
     * the attribute when we have the write lock here.
     */
    if (template_attribute_get_non_empty(key_obj->template,
                                         CKA_IBM_OPAQUE, &skey_attr) != CKR_OK) {
        TRACE_ERROR("This key has no blob: should not occur!\n");
        rc = CKR_FUNCTION_FAILED;
        goto unlock;
    }

retry:
    /* Convert secure key to protected key. */
    rc = ccatok_pkey_skey2pkey(tokdata, skey_attr, &pkey_attr, xts_mode);
    if (rc != CKR_OK) {
        TRACE_ERROR("protkey creation failed, rc=0x%lx\n", rc);
        goto unlock;
    }

    /*
     * In case of XTS, check if the wkvp's of the two keys are identical.
     * An LGR could have happened between the creation of the two keys.
     */
    if (xts_mode) {
        vp_offset1 = pkey_attr->ulValueLen / 2 - PKEY_MK_VP_LENGTH;
        vp_offset2 = pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH;
        if (memcmp((CK_BYTE *)pkey_attr->pValue + vp_offset1,
                   (CK_BYTE *)pkey_attr->pValue + vp_offset2,
                   PKEY_MK_VP_LENGTH) != 0) {
            num_retries++;
            if (num_retries < PKEY_CONVERT_KEY_RETRIES) {
                TRACE_DEVEL("%s vp of xts key 1 does not match with vp of "
                            "xts key 2, retry %d of %d ...\n",
                            __func__, num_retries, PKEY_CONVERT_KEY_RETRIES);
                goto retry;
            }
            rc = CKR_FUNCTION_FAILED;
            goto unlock;
        }
    }

    /*
     * Save new protkey attr in key_obj. This happens only in memory,
     * works also for r/o sessions.
     */
    rc = template_update_attribute(key_obj->template, pkey_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed, rc=0x%lx\n", rc);
        goto unlock;
    }

    /* If we have a r/w session, also save obj to disk. */
    if (ccatok_pkey_session_ok_for_obj(session, key_obj)) {
        if (object_is_token_object(key_obj)) {
            rc = object_mgr_save_token_object(tokdata, key_obj);
            if (rc != CKR_OK) {
                TRACE_ERROR("Could not save token obj to repository, rc=0x%lx.\n", rc);
                goto unlock;
            }
        }
    }

    /* Update wkvp in CCA private data. */
    if (pthread_rwlock_wrlock(&cca_private->pkey_rwlock)) {
        TRACE_ERROR("%s Failed to lock pkey lock\n", __func__);
        rc = CKR_CANT_LOCK;
        goto unlock;
    }
    memcpy(&cca_private->pkey_mk_vp,
           (CK_BYTE *)pkey_attr->pValue + pkey_attr->ulValueLen - PKEY_MK_VP_LENGTH,
           PKEY_MK_VP_LENGTH);
    if (pthread_rwlock_unlock(&cca_private->pkey_rwlock)) {
        TRACE_ERROR("%s Failed to unlock pkey lock\n", __func__);
    }

    /* Pass back new protkey. Need to do this before unlocking the obj. */
    if (*protkey_len < pkey_attr->ulValueLen) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto unlock;
    }
    memcpy(protkey, pkey_attr->pValue, pkey_attr->ulValueLen);
    *protkey_len = pkey_attr->ulValueLen;

unlock:
    rc2 = object_unlock(key_obj);
    if (rc2 != CKR_OK) {
        TRACE_ERROR("object_unlock failed, rc=0x%lx\n", rc2);
        if (rc == CKR_OK)
            rc = rc2;
        goto done;
    }

    rc2 = object_lock(key_obj, READ_LOCK);
    if (rc2 != CKR_OK) {
        TRACE_ERROR("object_lock for READ failed, rc=0x%lx\n", rc2);
        if (rc == CKR_OK)
            rc = rc2;
        goto done;
    }

done:

    return rc;
}
#endif

/*
 * This function is called whenever a new object is created. It sets
 * attribute CKA_IBM_PROTKEY_EXTRACTABLE according to the PKEY_MODE token
 * option.
 * If the FORCE_SENSITIVE token option is enabled, it sets attribute
 * CKA_SENSITIVE to TRUE for secret keys (CKO_SECRET_KEY) if it is not
 * specified in the template. For private keys (CKO_PRIVATE_KEY) it always
 * sets CKA_SENSITIVE to TRUE if it is not specified in the template,
 * regardless of the FORCE_SENSITIVE option.
 */
CK_RV token_specific_set_attrs_for_new_object(STDLL_TokData_t *tokdata,
                                              CK_OBJECT_CLASS class,
                                              CK_ULONG mode, TEMPLATE *tmpl)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ATTRIBUTE *sensitive_attr = NULL;
#ifndef NO_PKEY
    CK_ATTRIBUTE *pkey_attr = NULL, *ecp_attr = NULL;
    CK_BBOOL add_pkey_extractable = CK_FALSE;
#endif
    CK_BBOOL sensitive;
    CK_BBOOL btrue = CK_TRUE;
    CK_RV ret;

    UNUSED(mode);

    if (class != CKO_SECRET_KEY && class != CKO_PRIVATE_KEY &&
        class != CKO_PUBLIC_KEY)
        return CKR_OK;

    if (class == CKO_PRIVATE_KEY ||
        (class == CKO_SECRET_KEY && cca_data->cka_sensitive_default_true)) {
        /* private key, or secret key and FORCE_SENSITIVE is enabled */
        ret = template_attribute_get_bool(tmpl, CKA_SENSITIVE, &sensitive);
        if (ret == CKR_TEMPLATE_INCOMPLETE) {
            /* Not in template, supply default (TRUE) */
            ret = build_attribute(CKA_SENSITIVE, &btrue, sizeof(CK_BBOOL),
                                  &sensitive_attr);
            if (ret != CKR_OK) {
                TRACE_ERROR("build_attribute failed with ret=0x%lx\n", ret);
                goto done;
            }
            ret = template_update_attribute(tmpl, sensitive_attr);
            if (ret != CKR_OK) {
                TRACE_ERROR("update_attribute failed with ret=0x%lx\n", ret);
                free(sensitive_attr);
                goto done;
            }
        }
    }

#ifndef NO_PKEY
    switch (cca_data->pkey_mode) {
    case PKEY_MODE_DISABLED:
        /* Nothing to do */
        break;
    case PKEY_MODE_DEFAULT:
        /*
         * If the application did not specify pkey-extractable, all keys get
         * pkey-extractable=false. This was already set by default, so
         * nothing to do here.
         */
        break;
    case PKEY_MODE_ENABLED:
        /*
         * All secret/private keys and all EC public keys where CPACF supports
         * the related curve, get pkey-extractable=true
         */
        switch (class) {
        case CKO_PUBLIC_KEY:
            if (template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &ecp_attr) == CKR_OK &&
                pkey_op_supported_by_cpacf(cca_data->msa_level, CKM_ECDSA, tmpl))
                add_pkey_extractable = CK_TRUE;
                /*
                 * Note that the explicit parm CKM_ECDSA just tells the
                 * function that it's not AES here. It covers all EC mechs
                 */
            break;
        default:
            add_pkey_extractable = CK_TRUE;
            break;
        }

        if (add_pkey_extractable) {
            if (!template_attribute_find(tmpl, CKA_IBM_PROTKEY_EXTRACTABLE, &pkey_attr)) {
                ret = build_attribute(CKA_IBM_PROTKEY_EXTRACTABLE,
                                      (CK_BBOOL *)&btrue, sizeof(CK_BBOOL),
                                      &pkey_attr);
                if (ret != CKR_OK) {
                    TRACE_ERROR("build_attribute failed with ret=0x%lx\n", ret);
                    goto done;
                }
                ret = template_update_attribute(tmpl, pkey_attr);
                if (ret != CKR_OK) {
                    TRACE_ERROR("update_attribute failed with ret=0x%lx\n", ret);
                    free(pkey_attr);
                    goto done;
                }
            }
        }
        break;
    default:
        TRACE_ERROR("PKEY_MODE %i unsupported.\n", cca_data->pkey_mode);
        ret = CKR_FUNCTION_FAILED;
        goto done;
        break;
    }
#endif

    ret = CKR_OK;

done:

    return ret;
}


static CK_RV cca_get_and_set_aes_key_mode(STDLL_TokData_t *tokdata,
                                          TEMPLATE *tmpl,
                                          CK_IBM_CCA_AES_KEY_MODE_TYPE *mode)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    if (template_attribute_find(tmpl, CKA_IBM_CCA_AES_KEY_MODE, &attr)) {
        if (attr->ulValueLen != sizeof(CK_IBM_CCA_AES_KEY_MODE_TYPE) ||
            attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        *mode = *(CK_IBM_CCA_AES_KEY_MODE_TYPE *)attr->pValue;
        switch (*mode) {
        case CK_IBM_CCA_AES_DATA_KEY:
        case CK_IBM_CCA_AES_CIPHER_KEY:
            TRACE_DEVEL("AES key mode (attribute): %lu\n", *mode);
            return CKR_OK;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    switch (cca_data->aes_key_mode) {
    case AES_KEY_MODE_DATA:
        *mode = CK_IBM_CCA_AES_DATA_KEY;
        break;
    case AES_KEY_MODE_CIPHER:
        *mode = CK_IBM_CCA_AES_CIPHER_KEY;
        break;
    default:
        TRACE_DEVEL("Invalid AES key mode: %d\n", cca_data->aes_key_mode);
        return CKR_FUNCTION_FAILED;
    }

    rc = build_update_attribute(tmpl, CKA_IBM_CCA_AES_KEY_MODE,
                                (CK_BYTE *)mode, sizeof(*mode));
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_update_attribute(CKA_IBM_CCA_AES_KEY_MODE) failed\n");
        return rc;
    }

    TRACE_DEVEL("AES key mode (config): %lu\n", *mode);

    return CKR_OK;
}

static CK_RV ccatok_var_sym_token_is_exportable(const CK_BYTE *token,
                                                CK_ULONG token_len,
                                                CK_BBOOL *exportable,
                                                CK_BBOOL *cpacf_exportable)
{
    uint16_t key_mgmt1;

    if (token_len < CCA_VAR_SYM_TOKEN_KEYMGMT1_OFFSET + 1)
        return CKR_ARGUMENTS_BAD;

    key_mgmt1 =
            be16toh(*((uint16_t *)&token[CCA_VAR_SYM_TOKEN_KEYMGMT1_OFFSET]));

    if (cpacf_exportable != NULL)
#ifndef NO_PKEY
        *cpacf_exportable = (key_mgmt1 & CCA_VAR_SYM_XPRT_CPACF) != 0;
#else
        *cpacf_exportable = FALSE;
#endif

    if (exportable != NULL) {
        *exportable = (key_mgmt1 & (CCA_VAR_SYM_XPRT_SYM |
                                    CCA_VAR_SYM_XPRT_UASYM |
                                    CCA_VAR_SYM_XPRT_AASYM)) != 0;
        *exportable &= (key_mgmt1 & (CCA_VAR_SYM_NOEX_DES |
                                     CCA_VAR_SYM_NOEX_AES |
                                     CCA_VAR_SYM_NOEX_RSA)) == 0;
    }

    return CKR_OK;
}

#ifndef NO_PKEY

static CK_BBOOL ccatok_ecc_token_is_cpacf_exportable(const CK_BYTE *token,
                                                     CK_ULONG token_len)
{
    CK_BYTE keyusage = token[CCA_ECC_TOKEN_KEYUSAGE_OFFSET];

    if (token_len < CCA_ECC_TOKEN_KEYUSAGE_OFFSET)
        return CK_FALSE;

    if (keyusage & CCA_XPRTCPAC)
        return CK_TRUE;

    return CK_FALSE;
}

CK_RV ccatok_pkey_check_aes_xts(TEMPLATE *tmpl)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(tmpl, CKA_IBM_PROTKEY_EXTRACTABLE, &val);
    if (rc != CKR_OK || val == TRUE)
        return CKR_TEMPLATE_INCONSISTENT;

    return CKR_OK;
}

CK_RV token_specific_aes_xts_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                     CK_BYTE **aes_key, CK_ULONG *len,
                                     CK_ULONG key_size, CK_BBOOL *is_opaque)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ULONG key_len, key_token_len = 2 * 900;
    unsigned char key_token[900] = { 0, };
    unsigned char key_form[CCA_KEYWORD_SIZE];
    unsigned char key_type[CCA_KEYWORD_SIZE];
    CK_BBOOL new_mk, new_mk2;
    CK_ATTRIBUTE *reenc_attr = NULL;
    CK_ULONG pl_ofs, pl_len;
    CK_IBM_CCA_AES_KEY_MODE_TYPE mode;
    CK_RV rc;

    if (cca_data->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!cca_data->pkey_wrap_supported) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    if (!ccatok_pkey_check_aes_xts(tmpl)) {
        TRACE_ERROR("%s CCA AES XTS is not supported\n", __func__);
        return CKR_TEMPLATE_INCONSISTENT;
    }

    switch (key_size / 2) {
    case 16:
    case 32:
        break;
    default:
        TRACE_ERROR("Invalid key length: %lu\n", key_size);
        return CKR_KEY_SIZE_RANGE;
    }

    rc = cca_get_and_set_aes_key_mode(tokdata, tmpl, &mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("cca_get_and_set_aes_key_mode failed\n");
        return rc;
    }

    if (mode == CK_IBM_CCA_AES_CIPHER_KEY)
        key_token_len = CCA_MAX_AES_CIPHER_KEY_SIZE;
    else
        key_token_len = CCA_KEY_ID_SIZE;

    *aes_key = calloc(key_token_len * 2, 1);
    if (*aes_key == NULL)
        return CKR_HOST_MEMORY;
    *len = key_token_len * 2;
    *is_opaque = TRUE;

    if (mode == CK_IBM_CCA_AES_CIPHER_KEY)
        rc = cca_build_aes_cipher_token(tokdata, tmpl,
                                        key_token, &key_token_len);
    else
        rc = cca_build_aes_data_token(tokdata, key_size / 2,
                                      key_token, &key_token_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build CCA key token");
        /* Caller will free returned aes_key */
        return CKR_DEVICE_ERROR;
    }

    memcpy(key_form, "OP      ", CCA_KEYWORD_SIZE);
    if (mode == CK_IBM_CCA_AES_CIPHER_KEY)
        memcpy(key_type, "TOKEN   ", CCA_KEYWORD_SIZE);
    else
        memcpy(key_type, "AESTOKEN", CCA_KEYWORD_SIZE);

retry:
    memcpy(*aes_key, key_token, key_token_len);

    if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
        key_len = *len / 2;
        rc = cca_cipher_key_gen(tokdata, tmpl, CCA_AES_KEY, *aes_key, &key_len,
                                key_form, key_type, key_size / 2,
                                FALSE, &new_mk);
    } else {
        key_len = CCA_KEY_ID_SIZE;
        rc = cca_key_gen(tokdata, tmpl, CCA_AES_KEY, *aes_key, key_form,
                         key_type, key_size / 2, FALSE, &new_mk);
    }
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_%skey_gen function failed: rc=0x%lx\n",
                    mode == CK_IBM_CCA_AES_CIPHER_KEY ? "cipher_" : "", rc);
        return rc;
    }

    memcpy(*aes_key + key_len, key_token, key_token_len);

    if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
        rc = cca_cipher_key_gen(tokdata, tmpl, CCA_AES_KEY, *aes_key + key_len,
                                &key_len, key_form, key_type, key_size / 2,
                                TRUE, &new_mk2);
    } else {
        rc = cca_key_gen(tokdata, tmpl, CCA_AES_KEY, *aes_key + key_len,
                         key_form, key_type, key_size / 2, TRUE, &new_mk2);
    }
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_%skey_gen function failed: rc=0x%lx\n",
                    mode == CK_IBM_CCA_AES_CIPHER_KEY ? "cipher_" : "", rc);
        return rc;
    }

    if (new_mk == FALSE && new_mk2 == TRUE) {
        /*
         * Key 2 was created with new MK, key 1 with old MK.
         * Key 2 has CKA_IBM_OPAQUE and CKA_IBM_OPAQUE_REENC both
         * with new MK (was set by cca_reencipher_created_key() called inside
         * cca_key_gen()).
         * Key 1 has CKA_IBM_OPAQUE with old MK, and CKA_IBM_OPAQUE_REENC
         * with new MK (it was re-enciphered by cca_reencipher_created_key()
         * called inside 2nd cca_key_gen()).
         * Supply CKA_IBM_OPAQUE_REENC with new MK in CKA_IBM_OPAQUE
         * for key 1 also, so that both, CKA_IBM_OPAQUE and
         * CKA_IBM_OPAQUE_REENC have new MK only for both key parts.
         */
        rc = template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE_REENC,
                                              &reenc_attr);
        if (rc != CKR_OK || reenc_attr == NULL ||
            reenc_attr->ulValueLen != key_len * 2) {
            TRACE_ERROR("No CKA_IBM_OPAQUE_REENC attr found\n");
            return CKR_TEMPLATE_INCOMPLETE;
        }

        memcpy(*aes_key, reenc_attr->pValue, key_len);
    } else if (new_mk == TRUE && new_mk2 == FALSE) {
        /*
         * Key 1 was created with new MK, but key 2 with old MK.
         * This can happen when an APQN with new MK went offline
         * and another APQN with old MK is selected after creating
         * key 1 but before creating key 2. Since there is no key 1 blob
         * with old MK in CKA_IBM_OPAQUE, we need to re-create both keys
         * (both with old MK now).
         */
        memset(*aes_key, 0, *len);
        goto retry;
    }

    /*
     * Compare the encrypted key material to ensure that the 2 key parts are
     * not the same.
     */
    if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
        /*
         * A CCA AES-CIPHER key blob contains the encrypted key material at a
         * variable position dependent on several length bytes
         */
        pl_ofs = 56 + (*aes_key)[34] +  (*aes_key)[35] + (*aes_key)[36];
        pl_len = (be16toh(*((uint16_t*)(*aes_key + 38))) + 7) / 8;
    } else {
        /*
         * A CCA AES-DATA key blob contains the encrypted key material at
         * offset 16, with a length of 32 bytes.
         */
        pl_ofs = 16;
        pl_len = 32;
    }
    if (pl_ofs + pl_len <= key_len &&
        memcmp(*aes_key + pl_ofs, *aes_key + key_len + pl_ofs, pl_len) == 0) {
        memset(*aes_key, 0, *len);
        goto retry;
    }

    *len = key_len * 2;

    return CKR_OK;
}

/**
 * This routine is currently only used when the operation is performed using
 * a protected key. Therefore we don't have (and don't need) an cca
 * fallback here.
 */
CK_RV token_specific_aes_xts(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj, CK_BYTE *init_v,
                             CK_BBOOL encrypt, CK_BBOOL initial,
                             CK_BBOOL final, CK_BYTE *iv)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;
    CK_MECHANISM mech = { CKM_AES_XTS, NULL, 0 };

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    /* CCA token protected key option */
    rc = ccatok_pkey_check(tokdata, session, key_obj, &mech);
    switch (rc) {
    case CKR_OK:
        rc = pkey_aes_xts(tokdata, session, key_obj, init_v,
                          in_data, in_data_len, out_data, out_data_len,
                          encrypt, initial, final, iv,
                          ccatok_pkey_convert_key);
        goto done;
    default:
        goto done;
    }

done:

    return rc;
}

static CK_RV import_aes_xts_key(STDLL_TokData_t *tokdata,
                                OBJECT * object)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;
    enum cca_token_type token_type, token_type2;
    unsigned int token_keybitsize, token_keybitsize2;
    const CK_BYTE *mkvp, *mkvp2;
    CK_BBOOL new_mk, new_mk2;
    CK_ATTRIBUTE *reenc_attr = NULL;
    CK_ULONG pl_ofs, pl_len;

    if (!((struct cca_private_data *)tokdata->private_data)->pkey_wrap_supported) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    if (!ccatok_pkey_check_aes_xts(object->template)) {
        TRACE_ERROR("%s CCA AES XTS is not supported\n", __func__);
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rc = template_attribute_find(object->template, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure key which is stored in
         * the CKA_IBM_OPAQUE attribute. The CKA_VALUE attribute is only
         * a dummy reflecting the clear key byte size. However, let's
         * check if the template attributes match to the cca key in the
         * CKA_IBM_OPAQUE attribute.
         */
        CK_BYTE zorro[64] = { 0 };
        CK_BBOOL true = TRUE;
        CK_ULONG value_len = 0;
        CK_BBOOL exp, cpacf_exp, exp2 = FALSE, cpacf_exp2 = FALSE;
        CK_IBM_CCA_AES_KEY_MODE_TYPE mode;

        if (analyse_cca_key_token(opaque_attr->pValue,
                                  opaque_attr->ulValueLen / 2, &token_type,
                                  &token_keybitsize, &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (token_type == sec_aes_data_key) {
            /* keybitsize has been checked by the analyse_cca_key_token() function */
            mode = CK_IBM_CCA_AES_DATA_KEY;
        } else if (token_type == sec_aes_cipher_key) {
            mode = CK_IBM_CCA_AES_CIPHER_KEY;
            if (token_keybitsize == 0) {
                /*
                 * A CIPHER key with V1 payload does not allow to obtain the
                 * keybitsize. The user must supply the CKA_VALUE_LEN with
                 * a valid key size in the template.
                 */
                rc = template_attribute_get_ulong(object->template,
                                                  CKA_VALUE_LEN,
                                                  &value_len);
                if (rc != CKR_OK || value_len == 0) {
                    TRACE_ERROR("For an AES CIPHER key token with V1 "
                                "payload attribute CKA_VALUE_LEN must also "
                                "be supplied to specify the key size\n");
                    return CKR_TEMPLATE_INCONSISTENT;
                }
                if (value_len != 32 && value_len != 64) {
                    TRACE_ERROR("CKA_VALUE_LEN not valid for an AES key\n");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                token_keybitsize = value_len / 2 * 8;
            }

            rc = ccatok_var_sym_token_is_exportable(opaque_attr->pValue,
                                                    opaque_attr->ulValueLen,
                                                    &exp, &cpacf_exp);
            if (rc != CKR_OK)
                return rc;
        } else {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_AES\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, object->template,
                                        opaque_attr->pValue,
                                        opaque_attr->ulValueLen / 2,
                                        new_mk, token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        if (analyse_cca_key_token(((CK_BYTE *)opaque_attr->pValue) +
                                      (opaque_attr->ulValueLen / 2),
                                  opaque_attr->ulValueLen / 2, &token_type2,
                                  &token_keybitsize2, &mkvp2) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (token_type2 == sec_aes_data_key) {
            /* keybitsize has been checked by the analyse_cca_key_token() function */
            ;
        } else if (token_type2 == sec_aes_cipher_key) {
            if (token_keybitsize2 == 0) {
                /*
                 * A CIPHER key with V1 payload does not allow to obtain the
                 * keybitsize. The user must supply the CKA_VALUE_LEN with
                 * a valid key size in the template.
                 */
                rc = template_attribute_get_ulong(object->template,
                                                  CKA_VALUE_LEN,
                                                  &value_len);
                if (rc != CKR_OK || value_len == 0) {
                    TRACE_ERROR("For an AES CIPHER key token with V1 "
                                "payload attribute CKA_VALUE_LEN must also "
                                "be supplied to specify the key size\n");
                    return CKR_TEMPLATE_INCONSISTENT;
                }
                if (value_len != 32 && value_len != 64) {
                    TRACE_ERROR("CKA_VALUE_LEN not valid for an AES key\n");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                token_keybitsize2 = value_len / 2 * 8;
            }

            rc = ccatok_var_sym_token_is_exportable(opaque_attr->pValue,
                                                    opaque_attr->ulValueLen,
                                                    &exp2, &cpacf_exp2);
            if (rc != CKR_OK)
                return rc;
        } else {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_AES\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        if (check_expected_mkvp(tokdata, token_type2, mkvp2, &new_mk2) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, object->template,
                                        ((CK_BYTE *)opaque_attr->pValue) +
                                            (opaque_attr->ulValueLen / 2),
                                        opaque_attr->ulValueLen / 2,
                                        new_mk2, token_type2, TRUE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        if (token_type != token_type2 ||
            memcmp(mkvp, mkvp2, CCA_MKVP_LENGTH) != 0 ||
            token_keybitsize != token_keybitsize2) {
            TRACE_ERROR("CCA AES XTS keys attribute value mismatch\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (token_type == sec_aes_cipher_key) {
            if (exp != exp2 || cpacf_exp != cpacf_exp2) {
                TRACE_ERROR("CCA AES XTS keys attribute value mismatch\n");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }

            rc = build_update_attribute(object->template, CKA_EXTRACTABLE,
                                        (CK_BYTE *)&exp, sizeof(exp));
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_update_attribute(CKA_EXTRACTABLE) "
                            "failed\n");
                return rc;
            }

#ifndef NO_PKEY
            rc = build_update_attribute(object->template,
                                        CKA_IBM_PROTKEY_EXTRACTABLE,
                                        (CK_BYTE *)&cpacf_exp,
                                        sizeof(cpacf_exp));
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_update_attribute(CKA_EXTRACTABLE) "
                            "failed\n");
                return rc;
            }
#endif
        }

        rc = build_update_attribute(object->template, CKA_IBM_CCA_AES_KEY_MODE,
                                    (CK_BYTE *)&mode, sizeof(mode));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_CCA_AES_KEY_MODE) "
                        "failed\n");
            return rc;
        }

        /*
         * Compare the encrypted key material to ensure that the 2 key parts are
         * not the same.
         */
        if (token_type == sec_aes_cipher_key) {
            /*
             * A CCA AES-CIPHER key blob contains the encrypted key material at a
             * variable position dependent on several length bytes
             */
            pl_ofs = 56 + ((CK_BYTE *)opaque_attr->pValue)[34] +
                          ((CK_BYTE *)opaque_attr->pValue)[35] +
                          ((CK_BYTE *)opaque_attr->pValue)[36];
            pl_len = (be16toh(*((uint16_t*)(
                        ((CK_BYTE *)opaque_attr->pValue) + 38))) + 7) / 8;
        } else {
            /*
             * A CCA AES-DATA key blob contains the encrypted key material at
             * offset 16, with a length of 32 bytes.
             */
            pl_ofs = 16;
            pl_len = 32;
        }
        if (pl_ofs + pl_len <= opaque_attr->ulValueLen / 2 &&
            memcmp(((CK_BYTE *)opaque_attr->pValue) + pl_ofs ,
                   ((CK_BYTE *)opaque_attr->pValue) +
                                   opaque_attr->ulValueLen / 2 + pl_ofs,
                   pl_len) == 0) {
            TRACE_ERROR("The 2 key parts of an AES-XTS key can not be the same\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        /* create a dummy CKA_VALUE attribute with the key bit size but all zero */
        rc = build_update_attribute(object->template, CKA_VALUE,
                                    zorro, token_keybitsize * 2 / 8);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute(CKA_VALUE) failed\n");
            return rc;
        }

        /* Add/update CKA_SENSITIVE */
        rc = build_update_attribute(object->template, CKA_SENSITIVE, &true,
                                    sizeof(CK_BBOOL));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for CKA_SENSITIVE failed. rc=0x%lx\n", rc);
            return rc;
        }

    } else {
        /*
         * This is an import of a clear key value which is to be transfered
         * into a CCA Data AES key now.
         */

        long return_code, reason_code, rule_array_count;
        unsigned char target_key_token[CCA_MAX_AES_CIPHER_KEY_SIZE * 2] = { 0 };
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
        long key_token_len, key_len;
        CK_ATTRIBUTE *value_attr = NULL;
        long reserved_1 = 0, key_part_len;
        CK_IBM_CCA_AES_KEY_MODE_TYPE mode;

        rc = template_attribute_get_non_empty(object->template, CKA_VALUE,
                                              &value_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Incomplete key template\n");
            return CKR_TEMPLATE_INCOMPLETE;
        }

        if (memcmp(value_attr->pValue,
                   ((CK_BYTE *)value_attr->pValue) + value_attr->ulValueLen / 2,
                   value_attr->ulValueLen / 2) == 0) {
            TRACE_ERROR("The 2 key parts of an AES-XTS key can not be the same\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        rc = cca_get_and_set_aes_key_mode(tokdata, object->template, &mode);
        if (rc != CKR_OK) {
            TRACE_DEVEL("cca_get_and_set_aes_key_mode failed\n");
            return rc;
        }

retry:
        if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
            memcpy(rule_array, "INTERNALAES     CIPHER  NO-KEY  ANY-MODE",
                   5 * CCA_KEYWORD_SIZE);
            rule_array_count = 5;

            rc = cca_aes_cipher_add_key_usage_keywords(tokdata,
                                                       object->template,
                                                       rule_array,
                                                       sizeof(rule_array),
                                                       (CK_ULONG *)
                                                           &rule_array_count);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to add key usage keywords\n");
                return rc;
            }

            key_len = sizeof(target_key_token) / 2;
            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &key_len, target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKTB2 (AES CIPHER KEY TOKEN BUILD) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }

            memcpy(rule_array, "AES     FIRST   MIN1PART",
                   3 * CCA_KEYWORD_SIZE);
            rule_array_count = 3;
            key_len = sizeof(target_key_token) / 2;
            key_part_len = value_attr->ulValueLen / 2 * 8;

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &key_part_len, value_attr->pValue,
                             &key_len, target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKPI2 (AES CIPHER KEY IMPORT FIRST) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }

            memcpy(rule_array, "AES     COMPLETE", 2 * CCA_KEYWORD_SIZE);
            rule_array_count = 2;

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &reserved_1, NULL,
                             &key_len, target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKPI2 (AES CIPHER KEY IMPORT COMPLETE) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }
            key_token_len = key_len;
        } else {
            memcpy(rule_array, "AES     ", CCA_KEYWORD_SIZE);
            rule_array_count = 1;

            key_part_len = value_attr->ulValueLen / 2;
            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBCKM(&return_code, &reason_code, NULL, NULL,
                            &rule_array_count, rule_array,
                            &key_part_len, value_attr->pValue,
                            target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBCKM failed. return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }
            key_token_len = CCA_KEY_ID_SIZE;
        }

        if (analyse_cca_key_token(target_key_token, key_token_len,
                                  &token_type, &token_keybitsize,
                                  &mkvp) == FALSE || mkvp == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, object->template,
                                        target_key_token, key_token_len, new_mk,
                                        token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
            memcpy(rule_array, "INTERNALAES     CIPHER  NO-KEY  ANY-MODE",
                   5 * CCA_KEYWORD_SIZE);
            rule_array_count = 5;

            rc = cca_aes_cipher_add_key_usage_keywords(tokdata,
                                                       object->template,
                                                       rule_array,
                                                       sizeof(rule_array),
                                                       (CK_ULONG *)
                                                           &rule_array_count);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to add key usage keywords\n");
                return rc;
            }

            key_len = sizeof(target_key_token) / 2;
            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &key_len, target_key_token + key_token_len);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKTB2 (AES CIPHER KEY TOKEN BUILD) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }

            memcpy(rule_array, "AES     FIRST   MIN1PART",
                   3 * CCA_KEYWORD_SIZE);
            rule_array_count = 3;
            key_len = sizeof(target_key_token) / 2;
            key_part_len = value_attr->ulValueLen / 2 * 8;

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &key_part_len, (CK_BYTE *)value_attr->pValue +
                                             value_attr->ulValueLen / 2,
                             &key_len, target_key_token + key_token_len);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKPI2 (AES CIPHER KEY IMPORT FIRST) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }

            memcpy(rule_array, "AES     COMPLETE", 2 * CCA_KEYWORD_SIZE);
            rule_array_count = 2;

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &reserved_1, NULL,
                             &key_len, target_key_token + key_token_len);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKPI2 (AES CIPHER KEY IMPORT COMPLETE) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }

            if (key_len != key_token_len) {
                TRACE_ERROR("Second XTS key part has different length than "
                            "first one\n");
                return CKR_FUNCTION_FAILED;
            }
        } else {
            key_part_len = value_attr->ulValueLen / 2;
            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBCKM(&return_code, &reason_code, NULL, NULL,
                            &rule_array_count, rule_array,
                            &key_part_len, (CK_BYTE *)value_attr->pValue +
                            value_attr->ulValueLen / 2,
                            target_key_token + key_token_len);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBCKM failed. return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }
        }

        if (analyse_cca_key_token(target_key_token + key_token_len,
                                  key_token_len, &token_type2,
                                  &token_keybitsize2, &mkvp2) == FALSE ||
            mkvp2 == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, token_type2, mkvp2, &new_mk2) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        if (new_mk == FALSE && new_mk2 == TRUE) {
            /*
             * Key 2 was created with new MK, key 1 with old MK.
             * Key 2 will have CKA_IBM_OPAQUE and CKA_IBM_OPAQUE_REENC both
             * with new MK (will be set by cca_reencipher_created_key() below).
             * Key 1 has CKA_IBM_OPAQUE with old MK, and CKA_IBM_OPAQUE_REENC
             * with new MK (it was re-enciphered by cca_reencipher_created_key()
             * above). Supply CKA_IBM_OPAQUE_REENC with new MK in CKA_IBM_OPAQUE
             * for key 1 also, so that both, CKA_IBM_OPAQUE and
             * CKA_IBM_OPAQUE_REENC have new MK only for both key parts.
             */
            rc = template_attribute_get_non_empty(object->template,
                                                  CKA_IBM_OPAQUE_REENC,
                                                  &reenc_attr);
            if (rc != CKR_OK || reenc_attr == NULL ||
                reenc_attr->ulValueLen != CCA_KEY_ID_SIZE) {
                TRACE_ERROR("No CKA_IBM_OPAQUE_REENC attr found\n");
                return CKR_TEMPLATE_INCOMPLETE;
            }

            memcpy(target_key_token, reenc_attr->pValue, key_token_len);
        } else if (new_mk == TRUE && new_mk2 == FALSE) {
            /*
             * Key 1 was created with new MK, but key 2 with old MK.
             * This can happen when an APQN with new MK went offline
             * and another APQN with old MK is selected after creating
             * key 1 but before creating key 2. Since there is no key 1 blob
             * with old MK in CKA_IBM_OPAQUE, we need to re-create both keys
             * (both with old MK now).
             */
            memset(target_key_token, 0, sizeof(target_key_token));
            goto retry;
        }

        rc = cca_reencipher_created_key(tokdata, object->template,
                                        target_key_token + key_token_len,
                                        CCA_KEY_ID_SIZE, new_mk2, token_type2,
                                        TRUE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        if (token_type != token_type2 ||
            memcmp(mkvp, mkvp2, CCA_MKVP_LENGTH) != 0 ||
            token_keybitsize != token_keybitsize2) {
            TRACE_ERROR("CCA AES XTS keys attribute value mismatch\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        /* Add the key object to the template */
        rc = build_update_attribute(object->template, CKA_IBM_OPAQUE,
                                    target_key_token, key_token_len * 2);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
            return rc;
        }

        /* zero clear key value */
        OPENSSL_cleanse(value_attr->pValue, value_attr->ulValueLen);
    }

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(object->template);

    return CKR_OK;
}

#endif /* NO_PKEY */

typedef struct {
    CK_BBOOL card_level_set;
    struct cca_version min_card_version;
} cca_min_card_version_t;

/* return -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2 */
static int compare_cca_version(const struct cca_version *v1,
                               const struct cca_version *v2)
{
    if (v1->ver < v2->ver)
        return -1;
    if (v1->ver > v2->ver)
        return 1;
    if (v1->rel < v2->rel)
        return -1;
    if (v1->rel > v2->rel)
        return 1;
    if (v1->mod < v2->mod)
        return -1;
    if (v1->mod > v2->mod)
        return 1;
    return 0;
}

/*
 * Called from within cca_iterate_adapters() handler function, thus no need to
 * obtain  CCA adapter lock
 */
static CK_RV cca_get_adapter_version(cca_min_card_version_t *data)
{
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, verb_data_length;
    struct cca_version adapter_version;
    char ccaversion[CCA_STATCCA_CCA_VERSION_LENGTH + 1];

    memcpy(rule_array, "STATCCA ", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    verb_data_length = 0;
    dll_CSUACFQ(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &verb_data_length, NULL);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACFQ (STATCCA) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    ccaversion[CCA_STATCCA_CCA_VERSION_LENGTH] = '\0';
    memcpy(ccaversion, &rule_array[CCA_STATCCA_CCA_VERSION_OFFSET],
           CCA_STATCCA_CCA_VERSION_LENGTH);

    if (sscanf(ccaversion, "%d.%d.%02d*", (int *)&adapter_version.ver,
               (int *)&adapter_version.rel, (int *)&adapter_version.mod) != 3) {
        TRACE_ERROR("sscanf of string %s failed, cannot determine CCA card version\n",
                    ccaversion);
        return CKR_FUNCTION_FAILED;
    }

    if (compare_cca_version(&adapter_version, &data->min_card_version) < 0) {
        data->min_card_version = adapter_version;
        data->card_level_set = 1;
    }

    return CKR_OK;
}

/*
 * Callback function used by cca_get_min_card_level() to determine the
 * minimum CCA card level among all available APQNs.
 */
static CK_RV cca_get_card_level_handler(STDLL_TokData_t *tokdata, const char *adapter,
                                unsigned short card, unsigned short domain,
                                void *handler_data)
{
    cca_min_card_version_t *data = (cca_min_card_version_t *) handler_data;

    UNUSED(tokdata);
    UNUSED(adapter);
    UNUSED(card);
    UNUSED(domain);

    return cca_get_adapter_version(data);
}

/* Called during token_specific_init() , no need to obtain CCA adapter lock */
static CK_RV cca_get_min_card_level(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    cca_min_card_version_t card_level_data;
    CK_RV ret;

    /* Determine min card level by iterating over all APQNs */
    memset(&card_level_data, 0, sizeof(cca_min_card_version_t));
    card_level_data.min_card_version.ver = UINT_MAX;
    card_level_data.min_card_version.rel = UINT_MAX;
    card_level_data.min_card_version.mod = UINT_MAX;

    ret = cca_iterate_adapters(tokdata, cca_get_card_level_handler,
                               &card_level_data);

    if (ret != CKR_OK || card_level_data.card_level_set == 0) {
        TRACE_ERROR("cca_iterate_adapters failed, could not determine min card level.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Update min card level in cca_private_data, needs write-lock. */
    if (pthread_rwlock_wrlock(&cca_private->min_card_version_rwlock) != 0) {
        TRACE_ERROR("CCA min_card_version RW-lock failed.\n");
        ret = CKR_CANT_LOCK;
        goto done;
    }

    cca_private->min_card_version = card_level_data.min_card_version;
    if (pthread_rwlock_unlock(&cca_private->min_card_version_rwlock) != 0) {
        TRACE_ERROR("CCA min_card_version RW-unlock failed.\n");
        ret = CKR_CANT_LOCK;
        goto done;
    }

    ret = CKR_OK;

done:

    return ret;
}

static CK_BBOOL cca_get_acp(struct cca_role_data *role_data,
                            CK_ULONG role_data_size, CK_ULONG acp_num)
{
    struct cca_acp_segment *acp_segment;
    CK_BBOOL ret = CK_FALSE, found = CK_FALSE;
    CK_BYTE *bitmap;
    CK_ULONG i, ofs, bit_no;

    if (role_data == NULL || role_data_size < sizeof(struct cca_role_data))
        goto out;

    ofs = sizeof(struct cca_role_data);
    for (i = 0; i < role_data->num_segments && ofs < role_data_size; i++) {
        if (ofs + sizeof(struct cca_acp_segment) > role_data_size)
            goto out;

        acp_segment =
              (struct cca_acp_segment *)((CK_BYTE*)role_data + ofs);
        ofs += sizeof(struct cca_acp_segment);

        if (acp_num >= acp_segment->start_bit_no &&
            acp_num <= acp_segment->end_bit_no) {
            if (ofs + acp_segment->num_bytes > role_data_size)
                goto out;

            bitmap = ((CK_BYTE *)acp_segment) + sizeof(struct cca_acp_segment);
            bit_no = acp_num - acp_segment->start_bit_no;

            if (ACP_BYTE_NO(bit_no) > acp_segment->num_bytes)
                goto out;

            ret = (bitmap[ACP_BYTE_NO(bit_no)] & ACP_BIT_MASK(bit_no)) != 0;
            found = CK_TRUE;
            goto out;
        }

        ofs += acp_segment->num_bytes;
    }

out:
    TRACE_DEVEL("ACP 0x%04lx: %s %s\n", acp_num, ret ? "enabled" : "disabled",
                found ? "" : "(not in any segment)");

    return ret;
}

typedef struct {
    CK_BBOOL acps_set;
    struct cca_acp_info acp_info;
} cca_acp_info_data_t;

/*
 * Callback function used by cca_get_acp_infos() to determine the
 * minimum ACP settings among all available APQNs.
 */
static CK_RV cca_get_acp_info_handler(STDLL_TokData_t *tokdata,
                                      const char *adapter,
                                      unsigned short card,
                                      unsigned short domain,
                                      void *handler_data)
{
    cca_acp_info_data_t *data = (cca_acp_info_data_t *)handler_data;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    unsigned char role_name[8] = { 0 };
    unsigned char roles_data[4000], role_data[4000];
    long return_code, reason_code, rule_array_count, roles_data_len;
    long i, role_data_len;
    struct cca_role_data *role_info;
    CK_BBOOL found = CK_FALSE;

    UNUSED(tokdata);
    UNUSED(adapter);

    TRACE_DEBUG("APQN %02X.%04X (adapter '%s')\n", card, domain, adapter);

    memcpy(rule_array, "LSTROLES", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    roles_data_len = sizeof(roles_data);

    dll_CSUAACM(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                role_name,
                &roles_data_len, roles_data);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUAACM (LSTROLES) failed for of APQN %02X.%04X. "
                    "return:%ld, reason:%ld\n", card, domain,
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    for (i = 0; i < roles_data_len / 8; i++) {
        memcpy(role_name, &roles_data[i * 8], 8);
        TRACE_DEVEL("Found role '%.8s' for APQN %02X.%04X\n", role_name,
                    card, domain);

        memcpy(rule_array, "GET-ROLE", CCA_KEYWORD_SIZE);
        rule_array_count = 1;
        role_data_len = sizeof(role_data);

        dll_CSUAACM(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    role_name,
                    &role_data_len, role_data);

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSUAACM (GET-ROLE) failed for APQN %02X.%04X. "
                        "return:%ld, reason:%ld\n", card, domain,
                        return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        TRACE_DEBUG_DUMP("Role-Data: ", (CK_BYTE *)role_data, role_data_len);

        if (role_data_len < (long)sizeof(struct cca_role_data)) {
            TRACE_ERROR("No role data is available for APQN %02X.%04X\n",
                        card, domain);
            return CKR_FUNCTION_FAILED;
        }

        role_info = (struct cca_role_data *)role_data;

        /* Identify default role */
        if ((memcmp(role_name, "DFLT", 4) != 0 &&    /* since z13 */
             memcmp(role_name, "DEFALT", 6) != 0) || /* before z13 */
            role_info->lower_time_limit != 0x0000 ||
            (role_info->upper_time_limit != 0x0000 &&
             role_info->upper_time_limit != 0x173b) || /* 23:59 */
            role_info->days_valid != 0xfe)
            continue;

        TRACE_DEVEL("Using ACPs of default role '%.8s' of APQN %02X.%04X\n",
                    role_name, card, domain);

        data->acp_info.acp_03B8 &= cca_get_acp(role_info, role_data_len, 0x3B8);
        data->acp_info.acp_03CD &= cca_get_acp(role_info, role_data_len, 0x3CD);

        data->acps_set = CK_TRUE;
        found = CK_TRUE;
        break;
    }

    if (!found) {
        TRACE_ERROR("No default role found\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/* Called during token_specific_init() , no need to obtain CCA adapter lock */
static CK_RV cca_get_acp_infos(STDLL_TokData_t *tokdata)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    cca_acp_info_data_t acp_info_data;
    CK_RV ret;

    /* Determine min ACP setting by iterating over all APQNs */
    memset(&acp_info_data, 0, sizeof(cca_acp_info_data_t));
    acp_info_data.acp_info.acp_03B8 = CK_TRUE;
    acp_info_data.acp_info.acp_03CD = CK_TRUE;

    ret = cca_iterate_adapters(tokdata, cca_get_acp_info_handler,
                               &acp_info_data);

    if (ret != CKR_OK || acp_info_data.acps_set == 0) {
        TRACE_ERROR("cca_iterate_adapters failed, could not determine ACPs.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    TRACE_DEVEL("ACP 0x03B8: %s\n",
                acp_info_data.acp_info.acp_03B8 ? "enabled" : "disabled");
    TRACE_DEVEL("ACP 0x03CD: %s\n",
                acp_info_data.acp_info.acp_03CD ? "enabled" : "disabled");

    /* Update ACP infos in cca_private_data, needs write-lock. */
    if (pthread_rwlock_wrlock(&cca_private->acp_info_rwlock) != 0) {
        TRACE_ERROR("CCA acp_info RW-lock failed.\n");
        ret = CKR_CANT_LOCK;
        goto done;
    }

    cca_private->acp_info = acp_info_data.acp_info;
    if (pthread_rwlock_unlock(&cca_private->acp_info_rwlock) != 0) {
        TRACE_ERROR("CCA acp_info RW-unlock failed.\n");
        ret = CKR_CANT_LOCK;
        goto done;
    }

    ret = CKR_OK;

done:
    return ret;
}

static CK_BBOOL cca_pqc_strength_supported(STDLL_TokData_t * tokdata,
                                           CK_MECHANISM_TYPE mech,
                                           CK_ULONG keyform)
{
    struct cca_private_data *cca_private = tokdata->private_data;
#ifdef __s390__
    const struct cca_version cca_v7_1 = { .ver = 7, .rel = 1, .mod = 0 };
    const struct cca_version cca_v8_0 = { .ver = 8, .rel = 0, .mod = 0 };
#else
    const struct cca_version cca_v7_2_43 = { .ver = 7, .rel = 2, .mod = 43 };
#endif
    const struct cca_version *required = NULL;
    CK_BBOOL ret;

    switch (mech) {
    case CKM_IBM_DILITHIUM:
        switch (keyform) {
        case CK_IBM_DILITHIUM_KEYFORM_ROUND2_65:
#ifdef __s390__
            required = &cca_v7_1;
#else
            required = &cca_v7_2_43;
#endif
            break;
#ifdef __s390__
        case CK_IBM_DILITHIUM_KEYFORM_ROUND2_87:
        case CK_IBM_DILITHIUM_KEYFORM_ROUND3_65:
        case CK_IBM_DILITHIUM_KEYFORM_ROUND3_87:
            required = &cca_v8_0;
            break;
#endif
        default:
            TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                        keyform);
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }

    if (pthread_rwlock_rdlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Lock failed.\n");
        return FALSE;
    }

    ret = (compare_cca_version(&cca_private->cca_lib_version, required) >= 0 &&
           compare_cca_version(&cca_private->min_card_version, required) >= 0);

    if (pthread_rwlock_unlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Unlock failed.\n");
        return FALSE;
    }

    return ret;
}

static CK_BBOOL cca_sha3_supported(STDLL_TokData_t *tokdata)
{
    CK_BBOOL ret;
#ifdef __s390__
    struct cca_private_data *cca_private = tokdata->private_data;
    const struct cca_version cca_v8_1 = { .ver = 8, .rel = 1, .mod = 0 };

    if (pthread_rwlock_rdlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Lock failed.\n");
        return FALSE;
    }

    ret = (compare_cca_version(&cca_private->cca_lib_version, &cca_v8_1) >= 0 &&
           compare_cca_version(&cca_private->min_card_version, &cca_v8_1) >= 0);

    if (pthread_rwlock_unlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Unlock failed.\n");
        return FALSE;
    }
#else
    UNUSED(tokdata);

    ret = CK_FALSE;
#endif

    return ret;
}

static CK_BBOOL cca_rsa_oaep_2_1_supported(STDLL_TokData_t *tokdata)
{
    CK_BBOOL ret;
#ifdef __s390__
    struct cca_private_data *cca_private = tokdata->private_data;
    const struct cca_version cca_v8_1 = { .ver = 8, .rel = 1, .mod = 0 };

    if (pthread_rwlock_rdlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Lock failed.\n");
        return FALSE;
    }

    ret = (compare_cca_version(&cca_private->cca_lib_version, &cca_v8_1) >= 0 &&
           compare_cca_version(&cca_private->min_card_version, &cca_v8_1) >= 0);

    if (pthread_rwlock_unlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Unlock failed.\n");
        return FALSE;
    }
#else
    UNUSED(tokdata);

    ret = CK_FALSE;
#endif

    return ret;
}

static CK_BBOOL cca_rsa_aeskw_supported(STDLL_TokData_t *tokdata,
                                        CK_KEY_TYPE key_type)
{
    CK_BBOOL supp = CK_FALSE;
#ifdef __s390__
    CK_BBOOL aes_supp;
    struct cca_private_data *cca_private = tokdata->private_data;
    const struct cca_version cca_v8_2 = { .ver = 8, .rel = 2, .mod = 0 };

    /*
     * The following ACPs must be enabled to support CKM_RSA_AES_KEY_WRAP
     * to wrap/unwrap certain key types:
     *
     * AES (requires CCA 8.2 or later):
     * - X'03B8' Symmetric Key Export - AES, CKM-RAKW
     * - X'03CD' Permit import of an AES key token from a PKCS#11
     *           CKM_RSA_AES_KEY_WRAP object
     *
     * Note: These ACPs are DISABLED by default, and must be explicitly enabled
     *       by the crypto card admin to use CKM_RSA_AES_KEY_WRAP.
     */

    if (pthread_rwlock_rdlock(&cca_private->acp_info_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA acp_info RD-Lock failed.\n");
        return FALSE;
    }

    aes_supp = cca_private->acp_info.acp_03B8 &&
               cca_private->acp_info.acp_03CD;

    if (pthread_rwlock_unlock(&cca_private->acp_info_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA acp_info RD-Unlock failed.\n");
        return FALSE;
    }

    switch (key_type) {
    case CKK_AES:
    case (CK_KEY_TYPE)-1:
        supp = aes_supp;
        break;
    default:
        return FALSE;
    }

    if (pthread_rwlock_rdlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Lock failed.\n");
        return FALSE;
    }

    supp = supp &&
           compare_cca_version(&cca_private->cca_lib_version,
                               &cca_v8_2) >= 0 &&
           compare_cca_version(&cca_private->min_card_version,
                               &cca_v8_2) >= 0;

    if (pthread_rwlock_unlock(&cca_private->min_card_version_rwlock)
                                                        != 0) {
        TRACE_ERROR("CCA min_card_version RD-Unlock failed.\n");
        return FALSE;
    }
#else
    UNUSED(tokdata);
    UNUSED(key_type);
#endif

    return supp;
}

CK_RV token_specific_init(STDLL_TokData_t * tokdata, CK_SLOT_ID SlotNumber,
                          char *conf_name)
{
    struct cca_private_data *cca_private;

    CK_RV rc;

    UNUSED(conf_name);

    TRACE_INFO("cca %s slot=%lu running\n", __func__, SlotNumber);

    /* Request the API layer to lock against HSM-MK-change state changes. */
    rc = init_hsm_mk_change_lock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("init_hsm_mk_change_lock failed.\n");
        return rc;
    }

    cca_private = calloc(1, sizeof(*cca_private));
    if (cca_private == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    tokdata->private_data = cca_private;
    cca_private->pkeyfd = -1;

    rc = cca_load_config_file(tokdata, conf_name);
    if (rc != CKR_OK)
        goto error;

    rc = ock_generic_filter_mechanism_list(tokdata,
                                           cca_mech_list, cca_mech_list_len,
                                           &(tokdata->mech_list),
                                           &(tokdata->mech_list_len));
    if (rc != CKR_OK) {
        TRACE_ERROR("Mechanism filtering failed!  rc = 0x%lx\n", rc);
        goto error;
    }

    cca_private->lib_csulcca = dlopen(CCASHAREDLIB, RTLD_GLOBAL | DYNLIB_LDFLAGS);
    if (cca_private->lib_csulcca == NULL) {
        OCK_SYSLOG(LOG_ERR, "%s: Error loading library: '%s' [%s]\n",
                   __func__, CCASHAREDLIB, dlerror());
        TRACE_ERROR("%s: Error loading shared library '%s' [%s]\n",
                    __func__, CCASHAREDLIB, dlerror());
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    rc = cca_resolve_lib_sym(cca_private->lib_csulcca);
    if (rc != CKR_OK)
        goto error;

    rc = cca_get_version(tokdata);
    if (rc != CKR_OK)
        goto error;

    rc = cca_get_adapter_domain_selection_infos(tokdata);
    if (rc != CKR_OK)
        goto error;

    rc = init_cca_adapter_lock(tokdata);
    if (rc != CKR_OK)
        goto error;

    rc = cca_mk_change_check_pending_ops(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to check for pending HSM MK change operations "
                    "rc=0x%lx\n", __func__, rc);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to check for pending HSM MK "
                   "change operations rc=0x%lx\n", tokdata->slot_id, rc);
        goto error;
    }

    rc = cca_check_mks(tokdata);
    if (rc != CKR_OK)
        goto error;

    if (pthread_rwlock_init(&cca_private->min_card_version_rwlock, NULL) != 0) {
        TRACE_ERROR("Initializing the min_card_version RW-Lock failed\n");
        rc = CKR_CANT_LOCK;
        goto error;
    }

    rc = cca_get_min_card_level(tokdata);
    if (rc != CKR_OK)
        goto error;

    if (pthread_rwlock_init(&cca_private->acp_info_rwlock, NULL) != 0) {
        TRACE_ERROR("Initializing the acp_info RW-Lock failed\n");
        rc = CKR_CANT_LOCK;
        goto error;
    }

    rc = cca_get_acp_infos(tokdata);
    if (rc != CKR_OK)
        goto error;

#ifndef NO_PKEY
    cca_private->msa_level = get_msa_level();
    TRACE_INFO("MSA level = %i\n", cca_private->msa_level);

    if (!ccatok_pkey_option_disabled(tokdata)) {
        cca_private->pkeyfd = open(PKEYDEVICE, O_RDWR);
        if (cca_private->pkeyfd >= 0) {
            TRACE_INFO("Opened /dev/pkey: file descriptor %d\n", cca_private->pkeyfd);
            rc = ccatok_pkey_get_firmware_wkvp(tokdata);
            if (rc != CKR_OK) {
                /*
                 * Could not save mk_vp in cca_data, pkey support not available.
                 * But the token should initialize ok, even if this happens.
                 * We are just running without protected key support, i.e. the
                 * pkey_wrap_supported flag in tokdata remains off.
                 */
                OCK_SYSLOG(LOG_WARNING,
                    "%s: Warning: Could not get mk_vp, protected key support not available.\n",
                        __func__);
                TRACE_WARNING(
                    "Could not get mk_vp, protected key support not available.\n");
            }
        } else {
            TRACE_WARNING("Could not open /dev/pkey, protected key support not available.\n");
        }
    }
#endif

    if (pthread_rwlock_init(&cca_private->pkey_rwlock, NULL) != 0) {
        TRACE_ERROR("Initializing PKEY lock failed.\n");
        rc = CKR_CANT_LOCK;
        goto error;
    }

    return CKR_OK;

error:
    token_specific_final(tokdata, FALSE);
    return rc;
}

CK_RV token_specific_final(STDLL_TokData_t *tokdata,
                           CK_BBOOL in_fork_initializer)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    CK_ULONG i;

    TRACE_INFO("cca %s running\n", __func__);

    destroy_cca_adapter_lock(tokdata);

    if (tokdata->mech_list != NULL)
        free(tokdata->mech_list);

    if (cca_private != NULL) {
        if (cca_private->lib_csulcca != NULL && !in_fork_initializer)
            dlclose(cca_private->lib_csulcca);
        cca_private->lib_csulcca = NULL;

        for (i = 0; i < CCA_NUM_MK_TYPES; i++) {
            if (cca_private->mk_change_ops[i].mk_change_active &&
                cca_private->mk_change_ops[i].apqns != NULL)
                free(cca_private->mk_change_ops[i].apqns);
        }

#ifndef NO_PKEY
        if (cca_private->pkeyfd >= 0)
            close(cca_private->pkeyfd);
#endif

        pthread_rwlock_destroy(&cca_private->min_card_version_rwlock);
        pthread_rwlock_destroy(&cca_private->acp_info_rwlock);
        pthread_rwlock_destroy(&cca_private->pkey_rwlock);

        free(cca_private);
    }
    tokdata->private_data = NULL;

    return CKR_OK;
}

static CK_RV cca_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                         enum cca_key_type type, CK_BYTE *key,
                         unsigned char *key_form, unsigned char *key_type_1,
                         CK_ULONG key_size, CK_BBOOL aes_xts_2dn_key,
                         CK_BBOOL *has_new_mk)
{

    long return_code, reason_code;
    unsigned char key_length[CCA_KEYWORD_SIZE];
    unsigned char key_type_2[CCA_KEYWORD_SIZE] = { 0, };
    unsigned char kek_key_identifier_1[CCA_KEY_ID_SIZE] = { 0, };
    unsigned char kek_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };
    unsigned char generated_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;
    CK_RV rc;

    if (type == CCA_DES_KEY) {
        switch (key_size) {
        case 8:
            memcpy(key_length, "KEYLN8  ", (size_t) CCA_KEYWORD_SIZE);
            break;
        case 16:
            memcpy(key_length, "DOUBLE-O", (size_t) CCA_KEYWORD_SIZE);
            break;
        case 24:
            memcpy(key_length, "TRIPLE-O", (size_t) CCA_KEYWORD_SIZE);
            break;
        default:
            TRACE_ERROR("Invalid key length: %lu\n", key_size);
            return CKR_KEY_SIZE_RANGE;
        }
    } else if (type == CCA_AES_KEY) {
        switch (key_size) {
        case 16:
            memcpy(key_length, "KEYLN16 ", CCA_KEYWORD_SIZE);
            break;
        case 24:
            memcpy(key_length, "KEYLN24 ", (size_t) CCA_KEYWORD_SIZE);
            break;
        case 32:
            memcpy(key_length, "        ", (size_t) CCA_KEYWORD_SIZE);
            break;
        default:
            TRACE_ERROR("Invalid key length: %lu\n", key_size);
            return CKR_KEY_SIZE_RANGE;
        }
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBKGN(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    key_form,
                    key_length,
                    key_type_1,
                    key_type_2,
                    kek_key_identifier_1,
                    kek_key_identifier_2, key, generated_key_identifier_2);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBKGN(KEYGEN) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(key, CCA_KEY_ID_SIZE,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been generated\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = cca_reencipher_created_key(tokdata, tmpl, key, CCA_KEY_ID_SIZE,
                                    new_mk, keytype, aes_xts_2dn_key);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        return rc;
    }

    if (has_new_mk != NULL)
        *has_new_mk = new_mk;

    return CKR_OK;
}

static CK_RV cca_cipher_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                enum cca_key_type type,
                                CK_BYTE *key, CK_ULONG *key_len,
                                unsigned char *key_form,
                                unsigned char *key_type_1,
                                CK_ULONG key_size, CK_BBOOL aes_xts_2dn_key,
                                CK_BBOOL *has_new_mk)
{

    long return_code, reason_code;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0x20, };
    long exit_data_len = 0, rule_array_count;
    unsigned char exit_data[4] = { 0, };
    unsigned char key_type_2[CCA_KEYWORD_SIZE] = "        ";
    long clear_key_bit_length, zero_length = 0, key_token_len;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;
    CK_RV rc;

    if (type == CCA_AES_KEY) {
        switch (key_size) {
        case 16:
        case 24:
        case 32:
            clear_key_bit_length = key_size * 8;
            break;
        default:
            TRACE_ERROR("Invalid key length: %lu\n", key_size);
            return CKR_KEY_SIZE_RANGE;
        }

        rule_array_count = 1;
        memcpy(rule_array, "AES     ", CCA_KEYWORD_SIZE);
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
           key_form, CCA_KEYWORD_SIZE);
    rule_array_count++;

    key_token_len = *key_len;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBKGN2(&return_code, &reason_code,
                     &exit_data_len, exit_data,
                     &rule_array_count, rule_array,
                     &clear_key_bit_length,
                     key_type_1, key_type_2,
                     &zero_length, NULL,
                     &zero_length, NULL,
                     &zero_length, NULL,
                     &zero_length, NULL,
                     &zero_length, NULL,
                     &zero_length, NULL,
                     &key_token_len, key,
                     &zero_length, NULL);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBKGN2(KEYGEN) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    *key_len = key_token_len;

    if (analyse_cca_key_token(key, key_token_len,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been generated\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = cca_reencipher_created_key(tokdata, tmpl, key, key_token_len,
                                    new_mk, keytype, aes_xts_2dn_key);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        return rc;
    }

    if (has_new_mk != NULL)
        *has_new_mk = new_mk;

    return CKR_OK;
}

CK_RV token_specific_des_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **des_key, CK_ULONG *len,
                                 CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    unsigned char key_form[CCA_KEYWORD_SIZE];
    unsigned char key_type_1[CCA_KEYWORD_SIZE];

    UNUSED(tmpl);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    *des_key = calloc(CCA_KEY_ID_SIZE, 1);
    if (*des_key == NULL)
        return CKR_HOST_MEMORY;
    *len = CCA_KEY_ID_SIZE;
    *is_opaque = TRUE;

    memcpy(key_form, "OP      ", (size_t) CCA_KEYWORD_SIZE);
    memcpy(key_type_1, "DATA    ", (size_t) CCA_KEYWORD_SIZE);

    return cca_key_gen(tokdata, tmpl, CCA_DES_KEY, *des_key, key_form,
                       key_type_1, keysize, FALSE, NULL);
}


CK_RV token_specific_des_ecb(STDLL_TokData_t * tokdata,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE encrypt)
{
    UNUSED(tokdata);
    UNUSED(in_data);
    UNUSED(in_data_len);
    UNUSED(out_data);
    UNUSED(out_data_len);
    UNUSED(key);
    UNUSED(encrypt);

    TRACE_INFO("Unsupported function reached.\n");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV token_specific_des_cbc(STDLL_TokData_t * tokdata,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE * init_v, CK_BYTE encrypt)
{
    long return_code, reason_code, rule_array_count, length;
    long pad_character = 0;
    //char iv[8] = { 0xfe, 0x43, 0x12, 0xed, 0xaa, 0xbb, 0xdd, 0x90 };
    unsigned char chaining_vector[CCA_OCV_SIZE];
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
    CK_BYTE *local_out = out_data;
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    /* We need to have 8 bytes more than the in data length in case CCA
     * adds some padding, although this extra 8 bytes may not be needed.
     * If *out_data_len is not 8 bytes larger than in_data_len, then
     * we'll malloc the needed space and get the data back from CCA in this
     * malloc'd buffer. If it turns out that the extra 8 bytes wasn't
     * needed, we just silently copy the data to the user's buffer and
     * free our malloc'd space, returning as normal. If the space was
     * needed, we return an error and no memory corruption happens. */
    if (*out_data_len < (in_data_len + 8)) {
        local_out = malloc(in_data_len + 8);
        if (!local_out) {
            TRACE_ERROR("Malloc of %lu bytes failed.\n", in_data_len + 8);
            return CKR_HOST_MEMORY;
        }
    }

    length = in_data_len;

    rule_array_count = 1;
    memcpy(rule_array, "CBC     ", (size_t) CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        if (encrypt) {
            dll_CSNBENC(&return_code, &reason_code, NULL, NULL, attr->pValue,
                        &length, in_data,
                        init_v,
                        &rule_array_count, rule_array, &pad_character,
                        chaining_vector, local_out);
        } else {
            dll_CSNBDEC(&return_code, &reason_code, NULL, NULL, attr->pValue,
                        &length, in_data,
                        init_v,
                        &rule_array_count, rule_array, chaining_vector, local_out);
        }
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        if (encrypt)
            TRACE_ERROR("CSNBENC (DES ENCRYPT) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
        else
            TRACE_ERROR("CSNBDEC (DES DECRYPT) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
        if (out_data != local_out)
            free(local_out);
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        if (encrypt)
            TRACE_WARNING("CSNBENC (DES ENCRYPT) succeeded, but"
                          " returned reason:%ld\n", reason_code);
        else
            TRACE_WARNING("CSNBDEC (DES DECRYPT) succeeded, but"
                          " returned reason:%ld\n", reason_code);
    }

    /* If we malloc'd a new buffer due to overflow concerns and the data
     * coming out turned out to be bigger than expected, return an error.
     *
     * Else, memcpy the data back to the user's buffer
     */
    if ((local_out != out_data) && ((CK_ULONG) length > *out_data_len)) {
        TRACE_DEVEL("CKR_BUFFER_TOO_SMALL: %ld bytes to write into %ld "
                    "bytes space\n", length, *out_data_len);
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        free(local_out);
        return CKR_BUFFER_TOO_SMALL;
    } else if (local_out != out_data) {
        memcpy(out_data, local_out, (size_t) length);
        free(local_out);
    }

    *out_data_len = length;

    return CKR_OK;
}

CK_RV token_specific_tdes_ecb(STDLL_TokData_t * tokdata,
                              CK_BYTE * in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE * out_data,
                              CK_ULONG * out_data_len,
                              OBJECT * key, CK_BYTE encrypt)
{
    UNUSED(tokdata);
    UNUSED(in_data);
    UNUSED(in_data_len);
    UNUSED(out_data);
    UNUSED(out_data_len);
    UNUSED(key);
    UNUSED(encrypt);

    TRACE_WARNING("Unsupported function reached.\n");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV token_specific_tdes_cbc(STDLL_TokData_t * tokdata,
                              CK_BYTE * in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE * out_data,
                              CK_ULONG * out_data_len,
                              OBJECT * key, CK_BYTE * init_v, CK_BYTE encrypt)
{
    /* Since keys are opaque objects in this token and there's only
     * one encipher command to CCA, we can just pass through */
    return token_specific_des_cbc(tokdata, in_data, in_data_len, out_data,
                                  out_data_len, key, init_v, encrypt);
}

static uint16_t cca_rsa_inttok_privkey_get_len(CK_BYTE * tok)
{
    return be16toh(*(uint16_t *)&tok[CCA_RSA_INTTOK_PRIVKEY_LENGTH_OFFSET]);
}

/* Extract modulus n from a priv key section within an CCA internal RSA private key token */
static CK_RV cca_rsa_inttok_privkeysec_get_n(CK_BYTE *sec, CK_ULONG *n_len, CK_BYTE *n)
{
    int n_len_offset, n_value_offset;
    uint16_t n_length;

    if (sec[0] == 0x30) {
        /* internal CCA RSA key token, 4096 bits, ME format */
        n_len_offset = CCA_RSA_INTTOK_PRIVKEY_ME_N_LENGTH_OFFSET;
        n_value_offset = CCA_RSA_INTTOK_PRIVKEY_ME_N_OFFSET;
    } else if (sec[0] == 0x31) {
        /* internal CCA RSA key token, 4096 bits, CRT format */
        n_len_offset = CCA_RSA_INTTOK_PRIVKEY_CRT_N_LENGTH_OFFSET;
        n_value_offset = CCA_RSA_INTTOK_PRIVKEY_CRT_N_OFFSET;
    } else {
        TRACE_ERROR("Invalid private key section identifier 0x%02hhx\n", sec[0]);
        return CKR_FUNCTION_FAILED;
    }

    n_length = be16toh(*(uint16_t *)&sec[n_len_offset]);
    if (n_length > (*n_len)) {
        TRACE_ERROR("Not enough room to return n (Got %lu, need %hu).\n",
                    *n_len, n_length);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(n, &sec[n_value_offset], (size_t) n_length);
    *n_len = n_length;

    return CKR_OK;
}

/* Extract exponent e from a pubkey section within an CCA internal RSA private key token */
static CK_RV cca_rsa_inttok_pubkeysec_get_e(CK_BYTE *sec, CK_ULONG *e_len, CK_BYTE *e)
{
    uint16_t e_length;

    if (sec[0] != 0x04) {
        TRACE_ERROR("Invalid public key section identifier 0x%02hhx\n", sec[0]);
        return CKR_FUNCTION_FAILED;
    }

    e_length = be16toh(*((uint16_t *) &sec[CCA_RSA_INTTOK_PUBKEY_E_LENGTH_OFFSET]));
    if (e_length > (*e_len)) {
        TRACE_ERROR("Not enough room to return e (Got %lu, need %hu).\n",
                    *e_len, e_length);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(e, &sec[CCA_RSA_INTTOK_PUBKEY_E_OFFSET], (size_t) e_length);
    *e_len = (CK_ULONG) e_length;

    return CKR_OK;
}

/* Get modulus n from an CCA external public RSA key token's pub key section  */
static CK_RV cca_rsa_exttok_pubkeysec_get_n(CK_BYTE *sec, CK_ULONG *n_len, CK_BYTE *n)
{
    uint16_t e_length, n_length, n_offset;

    if (sec[0] != 0x04) {
        TRACE_ERROR("Invalid public key section identifier 0x%02hhx\n", sec[0]);
        return CKR_FUNCTION_FAILED;
    }

    n_length = be16toh(*((uint16_t *)&sec[CCA_RSA_EXTTOK_PUBKEY_N_LENGTH_OFFSET]));
    e_length = be16toh(*((uint16_t *)&sec[CCA_RSA_INTTOK_PUBKEY_E_LENGTH_OFFSET]));
    n_offset = CCA_RSA_INTTOK_PUBKEY_E_OFFSET + e_length;

    if (n_length == 0) {
        TRACE_ERROR("n_length is 0 - pub section from priv key given ?!?.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (n_length > (*n_len)) {
        TRACE_ERROR("Not enough room to return n (Got %lu, need %hu).\n",
                    *n_len, n_length);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(n, &sec[n_offset], (size_t) n_length);
    *n_len = n_length;

    return CKR_OK;
}

/* Get exponent e from an CCA external public RSA key token's pub key section  */
static CK_RV cca_rsa_exttok_pubkeysec_get_e(CK_BYTE *sec, CK_ULONG *e_len, CK_BYTE *e)
{
    uint16_t e_length;

    if (sec[0] != 0x04) {
        TRACE_ERROR("Invalid public key section identifier 0x%02hhx\n", sec[0]);
        return CKR_FUNCTION_FAILED;
    }

    e_length = be16toh(*((uint16_t *) &sec[CCA_RSA_INTTOK_PUBKEY_E_LENGTH_OFFSET]));
    if (e_length > (*e_len)) {
        TRACE_ERROR("Not enough room to return e (Got %lu, need %hu).\n",
                    *e_len, e_length);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(e, &sec[CCA_RSA_INTTOK_PUBKEY_E_OFFSET], (size_t) e_length);
    *e_len = (CK_ULONG) e_length;

    return CKR_OK;
}

/* Pull n and e from RSA priv key token and add to template */
static CK_RV add_n_and_e_from_rsa_priv_key_to_templ(TEMPLATE *tmpl,
                                                    CK_BYTE *cca_rsa_priv_key_token)
{
    uint16_t privkey_len, pubkey_offset;
    CK_BYTE n[CCATOK_MAX_N_LEN], e[CCATOK_MAX_E_LEN];
    CK_ULONG n_len = CCATOK_MAX_N_LEN, e_len = CCATOK_MAX_E_LEN;
    CK_RV rv;
    CK_BYTE *tok = cca_rsa_priv_key_token;

    if (tok[0] != 0x1F) {
        TRACE_ERROR("Invalid cca rsa private key token identifier 0x%02hhx\n", tok[0]);
        return CKR_FUNCTION_FAILED;
    }

    privkey_len =
        cca_rsa_inttok_privkey_get_len(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET]);
    pubkey_offset = privkey_len + CCA_RSA_INTTOK_HDR_LENGTH;

    /* That's right, n is stored in the private key area. Get it there */
    rv = cca_rsa_inttok_privkeysec_get_n(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET],
                                         &n_len, n);
    if (rv != CKR_OK) {
        TRACE_DEVEL("cca_inttok_privkey_get_n() failed. rv=0x%lx\n", rv);
        return rv;
    }

    /* Get e */
    if ((rv = cca_rsa_inttok_pubkeysec_get_e(&tok[pubkey_offset], &e_len, e))) {
        TRACE_DEVEL("cca_inttok_pubkey_get_e() failed. rv=0x%lx\n", rv);
        return rv;
    }

    /* Add n's value to the template */
    rv = build_update_attribute(tmpl, CKA_MODULUS, n, n_len);
    if (rv != CKR_OK) {
        TRACE_DEVEL("add CKA_MODULUS attribute to template failed, rv=0x%lx\n", rv);
        return rv;
    }

    /* Add e's value to the template */
    rv = build_update_attribute(tmpl, CKA_PUBLIC_EXPONENT, e, e_len);
    if (rv != CKR_OK) {
        TRACE_DEVEL("add CKA_PUBLIC_EXPONENT attribute to template failed, rv=0x%lx\n", rv);
        return rv;
    }

    return CKR_OK;
}

#if 0
CK_RV
token_create_priv_key(TEMPLATE * priv_tmpl, CK_ULONG tok_len, CK_BYTE * tok)
{
    CK_BYTE n[CCATOK_MAX_N_LEN];
    CK_ULONG n_len = CCATOK_MAX_N_LEN;
    CK_RV rv;
    CK_ATTRIBUTE *opaque_key, *modulus;

    /* That's right, n is stored in the private key area. Get it there */
    if ((rv = cca_inttok_privkey_get_n(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET],
                                       &n_len, n))) {
        TRACE_DEVEL("cca_inttok_privkey_get_n() failed. rv=0x%lx", rv);
        return rv;
    }

    /* Add n's value to the template. We need to do this for the private
     * key as well as the public key because openCryptoki checks data
     * sizes against the size of the CKA_MODULUS attribute of whatever
     * key object it gets */
    if ((rv = build_attribute(CKA_MODULUS, n, n_len, &modulus))) {
        TRACE_DEVEL("build_attribute for n failed. rv=0x%lx", rv);
        return rv;
    }
    if ((rv = template_update_attribute(priv_tmpl, modulus))) {
        TRACE_DEVEL("template_update_attribute for n failed. rv=0x%lx\n", rv);
        goto error;
    }
    modulus = NULL;

    /* Add the opaque key object to the template */
    if ((rv = build_attribute(CKA_IBM_OPAQUE, tok, tok_len, &opaque_key))) {
        TRACE_DEVEL("build_attribute for opaque key failed. rv=0x%lx", rv);
        return rv;
    }
    if ((rv = template_update_attribute(priv_tmpl, opaque_key))) {
        TRACE_DEVEL("template_update_attribute for opaque key failed. "
                    "rv=0x%lx\n", rv);
        goto error;
    }
    opaque_key = NULL;

    return CKR_OK;

error:
    if (modulus != NULL)
        free(modulus);
    if (opaque_key != NULL)
        free(opaque_key);
    return rv;
}
#endif

CK_RV token_specific_rsa_generate_keypair(STDLL_TokData_t * tokdata,
                                          TEMPLATE * publ_tmpl,
                                          TEMPLATE * priv_tmpl)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

    long key_value_structure_length;
    long private_key_name_length, key_token_length;
    unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
    unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
    unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

    long regeneration_data_length;
    long priv_key_token_length, publ_key_token_length;
    unsigned char regeneration_data[CCA_REGENERATION_DATA_SIZE] = { 0, };
    unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
    unsigned char priv_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    unsigned char publ_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

    uint16_t size_of_e;
    uint16_t mod_bits, be_mod_bits;
    CK_ATTRIBUTE *pub_exp = NULL;
    CK_RV rv;
    CK_BYTE_PTR ptr;
    CK_ULONG tmpsize, tmpexp, tmpbits;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rv = template_attribute_get_ulong(publ_tmpl, CKA_MODULUS_BITS, &tmpbits);
    if (rv != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS_BITS for the key.\n");
        return rv;
    }
    mod_bits = tmpbits;

    /* If e is specified in the template, use it */
    rv = template_attribute_get_non_empty(publ_tmpl, CKA_PUBLIC_EXPONENT,
                                          &pub_exp);
    if (rv == CKR_OK) {
        /* Per CCA manual, we really only support 3 values here:        *
         * * 0 (generate random public exponent)                        *
         * * 3 or                                                       *
         * * 65537                                                      *
         * Trim the P11 value so we can check what's comming our way    */

        tmpsize = pub_exp->ulValueLen;
        ptr = p11_bigint_trim(pub_exp->pValue, &tmpsize);
        /* If we trimmed the number correctly, only 3 bytes are         *
         * sufficient to hold 65537 (0x010001)                          */
        if (tmpsize > 3)
            return CKR_TEMPLATE_INCONSISTENT;

        /* make pValue into CK_ULONG so we can compare */
        tmpexp = 0;
        memcpy((unsigned char *) &tmpexp + sizeof(CK_ULONG) - tmpsize,
               ptr, tmpsize);	/* right align (it's always big endian) */
        if (sizeof(CK_ULONG) == 64 / 8)
            tmpexp = be64toh(tmpexp);
        else
            tmpexp = be32toh(tmpexp);

        /* Check for one of the three allowed values */
        if ((tmpexp != 0) && (tmpexp != 3) && (tmpexp != 65537))
            return CKR_TEMPLATE_INCONSISTENT;


        size_of_e = htobe16((uint16_t)tmpsize);

        memcpy(&key_value_structure[CCA_PKB_E_SIZE_OFFSET],
               &size_of_e, (size_t) CCA_PKB_E_SIZE);
        memcpy(&key_value_structure[CCA_PKB_E_OFFSET], ptr, (size_t) tmpsize);
    }

    key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
    be_mod_bits = htobe16(mod_bits);
    memcpy(key_value_structure, &be_mod_bits, sizeof(uint16_t));

    /* One last check. CCA can't auto-generate a random public      *
     * exponent if the modulus length is more than 2048 bits        *
     * We should be ok checking the public exponent length in the   *
     * key_value_structure, since either the caller never           *
     * specified it or we trimmed it's size. The size should be     *
     * zero if the value is zero in both cases.                     *
     * public exponent has CCA_PKB_E_SIZE_OFFSET offset with        *
     * 2-bytes size                                                 */
    if (mod_bits > 2048 &&
        key_value_structure[CCA_PKB_E_SIZE_OFFSET] == 0x00 &&
        key_value_structure[CCA_PKB_E_SIZE_OFFSET + 1] == 0x00) {
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rule_array_count = 2;
    memcpy(rule_array, "RSA-AESCKEY-MGMT", (size_t) (CCA_KEYWORD_SIZE * 2));
    private_key_name_length = 0;
    key_token_length = CCA_KEY_TOKEN_SIZE;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKB(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    &key_value_structure_length, key_value_structure,
                    &private_key_name_length, private_key_name,
                    0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL,
                    &key_token_length, key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKB (RSA KEY TOKEN BUILD) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    rule_array_count = 1;
    memset(rule_array, 0, sizeof(rule_array));
    memcpy(rule_array, "MASTER  ", (size_t) CCA_KEYWORD_SIZE);
    priv_key_token_length = CCA_KEY_TOKEN_SIZE;
    regeneration_data_length = 0;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKG(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    &regeneration_data_length, regeneration_data,
                    &key_token_length, key_token,
                    transport_key_identifier,
                    &priv_key_token_length, priv_key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKG (RSA KEY GENERATE) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(priv_key_token, priv_key_token_length,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been generated\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rv = cca_reencipher_created_key(tokdata, priv_tmpl, priv_key_token,
                                    priv_key_token_length, new_mk, keytype,
                                    FALSE);
    if (rv != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rv);
        return rv;
    }

    TRACE_DEVEL("RSA secure key token generated. size: %ld\n",
                priv_key_token_length);

    rule_array_count = 0;
    publ_key_token_length = CCA_KEY_TOKEN_SIZE;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKX(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    &priv_key_token_length, priv_key_token,
                    &publ_key_token_length, publ_key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKX (PUBLIC KEY TOKEN EXTRACT) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    TRACE_DEVEL("RSA public key token extracted. size: %ld\n",
                publ_key_token_length);

    /* update priv template, add n, e and ibm opaque attr with priv key token */
    rv = add_n_and_e_from_rsa_priv_key_to_templ(priv_tmpl, priv_key_token);
    if (rv != CKR_OK) {
        TRACE_DEVEL("add_n_and_e_from_rsa_priv_key_to_templ failed. rv:%lu\n", rv);
        return rv;
    }
    rv = build_update_attribute(priv_tmpl, CKA_IBM_OPAQUE,
                                priv_key_token,
                                priv_key_token_length);
    if (rv != CKR_OK) {
        TRACE_DEVEL("add CKA_IBM_OPAQUE attribute to priv template failed, rv:%lu\n", rv);
        return rv;
    }

    /* update pub template, add n, e and ibm opaque attr with pub key token */
    rv = add_n_and_e_from_rsa_priv_key_to_templ(publ_tmpl, priv_key_token);
    if (rv != CKR_OK) {
        TRACE_DEVEL("add_n_and_e_from_rsa_priv_key_to_templ failed. rv:%lu\n", rv);
        return rv;
    }
    rv = build_update_attribute(publ_tmpl, CKA_IBM_OPAQUE,
                                publ_key_token,
                                publ_key_token_length);
    if (rv != CKR_OK) {
        TRACE_DEVEL("add CKA_IBM_OPAQUE attribute to publ template failed, rv:%lu\n", rv);
        return rv;
    }

    TRACE_DEBUG("%s: priv template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(priv_tmpl);
    TRACE_DEBUG("%s: publ template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(publ_tmpl);

    return CKR_OK;
}


CK_RV token_specific_rsa_encrypt(STDLL_TokData_t * tokdata,
                                 CK_BYTE * in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE * out_data,
                                 CK_ULONG * out_data_len, OBJECT * key_obj)
{
    long return_code, reason_code, rule_array_count, data_structure_length;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    CK_RV rc;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (*out_data_len > 512)
        *out_data_len = 512;

    rule_array_count = 1;
    memcpy(rule_array, "PKCS-1.2", CCA_KEYWORD_SIZE);

    data_structure_length = 0;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDPKE(&return_code,
                    &reason_code,
                    NULL, NULL,
                    &rule_array_count,
                    rule_array,
                    (long *) &in_data_len,
                    in_data,
                    &data_structure_length,  // must be 0
                    NULL,           // ignored
                    (long *) &(attr->ulValueLen),
                    attr->pValue,
                    (long *) out_data_len,
                    out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKE (RSA ENCRYPT) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDPKE (RSA ENCRYPT) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }

    return CKR_OK;
}

CK_RV token_specific_rsa_decrypt(STDLL_TokData_t * tokdata,
                                 CK_BYTE * in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE * out_data,
                                 CK_ULONG * out_data_len, OBJECT * key_obj)
{
    long return_code, reason_code, rule_array_count, data_structure_length;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    CK_RV rc;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (*out_data_len > 512)
        *out_data_len = 512;

    rule_array_count = 1;
    memcpy(rule_array, "PKCS-1.2", CCA_KEYWORD_SIZE);

    data_structure_length = 0;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDPKD(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *) &in_data_len,
                    in_data,
                    &data_structure_length,  // must be 0
                    NULL,           // ignored
                    (long *) &(attr->ulValueLen),
                    attr->pValue,
                    (long *) out_data_len,
                    out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    TRACE_DEVEL("CSNDPKD (RSA DECRYPT): return:%ld, reason:%ld\n",
                return_code, reason_code);

    rc = constant_time_select(constant_time_eq(return_code, CCA_SUCCESS),
                              CKR_OK, CKR_FUNCTION_FAILED);
    rc = constant_time_select(constant_time_eq(return_code, 8) &
                              constant_time_eq(reason_code, 66),
                              CKR_ENCRYPTED_DATA_INVALID, rc);

    return rc;
}

CK_RV token_specific_rsa_oaep_encrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data,
                                      CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len,
                                      CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    long return_code, reason_code, rule_array_count, data_structure_length;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    OBJECT *key_obj = NULL;
    CK_BBOOL oaep2_supported;
    CK_MECHANISM_TYPE mgf_mech;
    CK_RV rc;

    UNUSED(hash);
    UNUSED(hlen);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        goto done;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        goto done;
    }

    oaep = (CK_RSA_PKCS_OAEP_PARAMS *)ctx->mech.pParameter;
    if (oaep == NULL ||
        ctx->mech.ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    if (oaep->source == CKZ_DATA_SPECIFIED && oaep->ulSourceDataLen > 0) {
        TRACE_ERROR("CCA does not support non-empty OAEP source data\n");
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    rc = get_mgf_mech(oaep->mgf, &mgf_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("MGF mechanism is invalid.\n");
        goto done;
    }

    if (oaep->hashAlg != mgf_mech) {
        TRACE_ERROR("OAEP MGF must be the same digest as the hash algorithm\n");
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (*out_data_len > 512)
        *out_data_len = 512;

    oaep2_supported = cca_rsa_oaep_2_1_supported(tokdata);
    if (oaep2_supported)
        memcpy(rule_array, "PKOAEP2 ", CCA_KEYWORD_SIZE);
    else
        memcpy(rule_array, "PKCSOAEP", CCA_KEYWORD_SIZE);

    rule_array_count = 2;
    switch (oaep->hashAlg) {
    case CKM_SHA_1:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-1   ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA224:
        if (!oaep2_supported) {
            TRACE_ERROR("OAEP with SHA224 requires CCA 8.1 or later\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-224 ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA256:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-256 ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA384:
        if (!oaep2_supported) {
            TRACE_ERROR("OAEP with SHA384 requires CCA 8.1 or later\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-384 ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA512:
        if (!oaep2_supported) {
            TRACE_ERROR("OAEP with SHA512 requires CCA 8.1 or later\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-512 ", CCA_KEYWORD_SIZE);
        break;

    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    data_structure_length = 0;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDPKE(&return_code,
                    &reason_code,
                    NULL, NULL,
                    &rule_array_count,
                    rule_array,
                    (long *)&in_data_len,
                    in_data,
                    &data_structure_length,  // must be 0
                    NULL,           // ignored
                    (long *)&(attr->ulValueLen),
                    attr->pValue,
                    (long *)out_data_len,
                    out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKE (RSA ENCRYPT) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDPKE (RSA ENCRYPT) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV token_specific_rsa_oaep_decrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data,
                                      CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len,
                                      CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    long return_code, reason_code, rule_array_count, data_structure_length;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    OBJECT *key_obj = NULL;
    CK_BBOOL oaep2_supported;
    CK_MECHANISM_TYPE mgf_mech;
    CK_RV rc;

    UNUSED(hash);
    UNUSED(hlen);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        goto done;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        goto done;
    }

    oaep = (CK_RSA_PKCS_OAEP_PARAMS *)ctx->mech.pParameter;
    if (oaep == NULL ||
        ctx->mech.ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    if (oaep->source == CKZ_DATA_SPECIFIED && oaep->ulSourceDataLen > 0) {
        TRACE_ERROR("CCA does not support non-empty OAEP source data\n");
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    rc = get_mgf_mech(oaep->mgf, &mgf_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("MGF mechanism is invalid.\n");
        goto done;
    }

    if (oaep->hashAlg != mgf_mech) {
        TRACE_ERROR("OAEP MGF must be the same digest as the hash algorithm\n");
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (*out_data_len > 512)
        *out_data_len = 512;

    oaep2_supported = cca_rsa_oaep_2_1_supported(tokdata);
    if (oaep2_supported)
        memcpy(rule_array, "PKOAEP2 ", CCA_KEYWORD_SIZE);
    else
        memcpy(rule_array, "PKCSOAEP", CCA_KEYWORD_SIZE);

    rule_array_count = 2;
    switch (oaep->hashAlg) {
    case CKM_SHA_1:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-1   ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA224:
        if (!oaep2_supported) {
            TRACE_ERROR("OAEP with SHA224 requires CCA v8.1 or later\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-224 ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA256:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-256 ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA384:
        if (!oaep2_supported) {
            TRACE_ERROR("OAEP with SHA384 requires CCA v8.1 or later\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-384 ", CCA_KEYWORD_SIZE);
        break;

    case CKM_SHA512:
        if (!oaep2_supported) {
            TRACE_ERROR("OAEP with SHA512 requires CCA v8.1 or later\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-512 ", CCA_KEYWORD_SIZE);
        break;

    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    data_structure_length = 0;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDPKD(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *)&in_data_len,
                    in_data,
                    &data_structure_length,  // must be 0
                    NULL,           // ignored
                    (long *) &(attr->ulValueLen),
                    attr->pValue,
                    (long *)out_data_len,
                    out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    TRACE_DEVEL("CSNDPKD (RSA DECRYPT): return:%ld, reason:%ld\n",
                return_code, reason_code);

    rc = constant_time_select(constant_time_eq(return_code, CCA_SUCCESS),
                              CKR_OK, CKR_FUNCTION_FAILED);
    rc = constant_time_select(constant_time_eq(return_code, 8) &
                              constant_time_eq(reason_code, 2054),
                              CKR_ENCRYPTED_DATA_INVALID, rc);
    rc = constant_time_select(constant_time_eq(return_code, 8) &
                              constant_time_eq(reason_code, 2053),
                              CKR_ENCRYPTED_DATA_INVALID, rc);

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV token_specific_rsa_sign(STDLL_TokData_t * tokdata,
                              SESSION  * sess,
                              CK_BYTE * in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE * out_data,
                              CK_ULONG * out_data_len, OBJECT * key_obj)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long signature_bit_length;
    CK_ATTRIBUTE *attr;
    CK_RV rc;

    UNUSED(sess);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (*out_data_len > 512)
        *out_data_len = 512;

    rule_array_count = 1;
    memcpy(rule_array, "PKCS-1.1", CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSG(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *) &(attr->ulValueLen),
                    attr->pValue,
                    (long *) &in_data_len,
                    in_data,
                    (long *) out_data_len, &signature_bit_length, out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSG (RSA SIGN) failed. return :%ld, reason: %ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDDSG (RSA SIGN) succeeded, but "
                      "returned reason: %ld\n", reason_code);
    }

    return CKR_OK;
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t * tokdata,
                                SESSION  * sess,
                                CK_BYTE * in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE * out_data,
                                CK_ULONG out_data_len, OBJECT * key_obj)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    CK_RV rc;

    UNUSED(sess);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (out_data_len > 512)
        out_data_len = 512;

    rule_array_count = 1;
    memcpy(rule_array, "PKCS-1.1", CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSV(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *) &(attr->ulValueLen),
                    attr->pValue,
                    (long *) &in_data_len,
                    in_data, (long *) &out_data_len, out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code == 4 && reason_code == 429) {
        return CKR_SIGNATURE_INVALID;
    } else if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSV (RSA VERIFY) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        if (return_code == 8 && reason_code == 72) {
            /*
             * Return CKR_SIGNATURE_INVALID in case of return code 8 and
             * reason code 72 because we dont know why the RSA op failed
             * and it may have failed due to a tampered signature being
             * greater or equal to the modulus.
             */
            return CKR_SIGNATURE_INVALID;
        }
        return CKR_FUNCTION_FAILED;
    }

    if (reason_code != 0) {
        TRACE_WARNING("CSNDDSV (RSA VERIFY) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }
    return CKR_OK;
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata,
                                  SESSION  *sess,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data,
                                  CK_ULONG in_data_len,
                                  CK_BYTE *out_data,
                                  CK_ULONG *out_data_len)
{
    CK_RSA_PKCS_PSS_PARAMS *pss;
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long signature_bit_length, message_len;
    CK_ATTRIBUTE *attr;
    OBJECT *key_obj = NULL;
    CK_BYTE *message = NULL;
    CK_RV rc;

    UNUSED(sess);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        goto done;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        goto done;
    }

    pss = (CK_RSA_PKCS_PSS_PARAMS *)ctx->mech.pParameter;
    if (pss == NULL ||
        ctx->mech.ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    message_len = 4 + in_data_len;
    message = malloc(message_len);
    if (message == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    *((uint32_t *)message) = htobe32(pss->sLen);
    memcpy(message + 4, in_data, in_data_len);

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (*out_data_len > 512)
        *out_data_len = 512;

    rule_array_count = 2;
    switch (pss->hashAlg) {
    case CKM_SHA_1:
        if (pss->mgf != CKG_MGF1_SHA1) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-1   ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA224:
        if (pss->mgf != CKG_MGF1_SHA224) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-224 ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA256:
        if (pss->mgf != CKG_MGF1_SHA256) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-256 ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA384:
        if (pss->mgf != CKG_MGF1_SHA384) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-384 ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA512:
        if (pss->mgf != CKG_MGF1_SHA512) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-512 ", 2 * CCA_KEYWORD_SIZE);
        break;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSG(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *)&(attr->ulValueLen),
                    attr->pValue,
                    &message_len,
                    message,
                    (long *)out_data_len, &signature_bit_length, out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSG (RSA PSS SIGN) failed. return :%ld, reason: %ld\n",
                    return_code, reason_code);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDDSG (RSA PSS SIGN) succeeded, but "
                      "returned reason: %ld\n", reason_code);
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    if (message != NULL)
        free(message);

    return rc;
}

CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata,
                                    SESSION  *sess,
                                    SIGN_VERIFY_CONTEXT *ctx,
                                    CK_BYTE *in_data,
                                    CK_ULONG in_data_len,
                                    CK_BYTE *out_data,
                                    CK_ULONG out_data_len)
{
    CK_RSA_PKCS_PSS_PARAMS *pss;
    long return_code, reason_code, rule_array_count, message_len;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    OBJECT *key_obj = NULL;
    CK_BYTE *message = NULL;
    CK_RV rc;

    UNUSED(sess);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        goto done;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        goto done;
    }

    pss = (CK_RSA_PKCS_PSS_PARAMS *)ctx->mech.pParameter;
    if (pss == NULL ||
        ctx->mech.ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    message_len = 4 + in_data_len;
    message = malloc(message_len);
    if (message == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    *((uint32_t *)message) = htobe32(pss->sLen);
    memcpy(message + 4, in_data, in_data_len);

    /* The max value allowable by CCA for out_data_len is 512, so cap the
     * incoming value if its too large. CCA will throw error 8, 72 otherwise.
     */
    if (out_data_len > 512)
        out_data_len = 512;

    rule_array_count = 2;
    switch (pss->hashAlg) {
    case CKM_SHA_1:
        if (pss->mgf != CKG_MGF1_SHA1) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-1   ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA224:
        if (pss->mgf != CKG_MGF1_SHA224) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-224 ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA256:
        if (pss->mgf != CKG_MGF1_SHA256) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-256 ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA384:
        if (pss->mgf != CKG_MGF1_SHA384) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-384 ", 2 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA512:
        if (pss->mgf != CKG_MGF1_SHA512) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        memcpy(rule_array, "PKCS-PSSSHA-512 ", 2 * CCA_KEYWORD_SIZE);
        break;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSV(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *)&(attr->ulValueLen),
                    attr->pValue,
                    &message_len,
                    message,
                    (long *)&out_data_len, out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code == 4 && reason_code == 429) {
        rc = CKR_SIGNATURE_INVALID;
        goto done;
    } else if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSV (RSA PSS VERIFY) failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        if (return_code == 8 && reason_code == 72) {
            /*
             * Return CKR_SIGNATURE_INVALID in case of return code 8 and
             * reason code 72 because we dont know why the RSA op failed
             * and it may have failed due to a tampered signature being
             * greater or equal to the modulus.
             */
            rc = CKR_SIGNATURE_INVALID;
            goto done;
        }
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (reason_code != 0) {
        TRACE_WARNING("CSNDDSV (RSA PSS VERIFY) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    if (message != NULL)
        free(message);

    return rc;
}

static CK_RV cca_aes_cipher_add_key_usage_keywords(STDLL_TokData_t *tokdata,
                                                   TEMPLATE *tmpl,
                                                   CK_BYTE *rule_array,
                                                   CK_ULONG rule_array_size,
                                                   CK_ULONG *rule_array_count)
{
    CK_BBOOL extractable = TRUE;
    CK_RV rc;

#ifdef NO_PKEY
    UNUSED(tokdata);
#endif

    rc = template_attribute_get_bool(tmpl, CKA_EXTRACTABLE, &extractable);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
        TRACE_ERROR("Failed to get CKA_EXTRACTABLE\n");
        return rc;
    }

    if (!extractable) {
        if ((*rule_array_count + 6) * CCA_KEYWORD_SIZE > rule_array_size)
            return CKR_BUFFER_TOO_SMALL;

        memcpy(rule_array + (*rule_array_count * CCA_KEYWORD_SIZE),
               "NOEX-SYMNOEXUASYNOEXAASYNOEX-DESNOEX-AESNOEX-RSA",
               6 * CCA_KEYWORD_SIZE);
        (*rule_array_count) += 6;
    }

#ifndef NO_PKEY
    /* Add protected key related attributes to the rule array */
    rc = ccatok_pkey_add_attrs(tokdata, tmpl, CKK_AES, 0, 0,
                               CK_IBM_CCA_AES_CIPHER_KEY, rule_array,
                               rule_array_size, rule_array_count);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ccatok_pkey_add_attrs failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }
#endif /* NO_PKEY */

    return CKR_OK;
}

static CK_RV cca_build_aes_cipher_token(STDLL_TokData_t *tokdata,
                                        TEMPLATE *tmpl, CK_BYTE *key_token,
                                        CK_ULONG *key_token_size)
{
    long return_code, reason_code;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long exit_data_len = 0, rule_array_count;
    unsigned char exit_data[4] = { 0, };
    long reserved_1 = 0;
    long key_token_len;
    CK_RV rc;

    rule_array_count = 5;
    memcpy(rule_array, "INTERNALAES     CIPHER  NO-KEY  ANY-MODE",
           5 * CCA_KEYWORD_SIZE);

    rc = cca_aes_cipher_add_key_usage_keywords(tokdata, tmpl, rule_array,
                                               sizeof(rule_array),
                                               (CK_ULONG *)&rule_array_count);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to add key usage keywords\n");
        return rc;
    }

    key_token_len = *key_token_size;
    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBKTB2(&return_code, &reason_code,
                     &exit_data_len, exit_data,
                     &rule_array_count, rule_array,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &key_token_len, key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBKTB2 (AES CIPHER KEY TOKEN BUILD) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    *key_token_size = key_token_len;

    return CKR_OK;
}

static CK_RV cca_build_aes_data_token(STDLL_TokData_t *tokdata,
                                      CK_ULONG key_size,
                                      CK_BYTE *key_token,
                                      CK_ULONG *key_token_size)
{
    long return_code, reason_code;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    unsigned char key_type[CCA_KEYWORD_SIZE];
    unsigned char point_to_array_of_zeros = 0;
    unsigned char mkvp[16] = { 0, };
    long exit_data_len = 0, rule_array_count;
    unsigned char exit_data[4] = { 0, };
    unsigned char reserved_1[4] = { 0, };

    if (*key_token_size < CCA_KEY_ID_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(rule_array, "INTERNALAES     NO-KEY  ", CCA_KEYWORD_SIZE * 3);
    memcpy(key_type, "DATA    ", CCA_KEYWORD_SIZE);

    switch (key_size) {
    case 16:
        memcpy(rule_array + 3 * CCA_KEYWORD_SIZE, "KEYLN16 ", CCA_KEYWORD_SIZE);
        break;
    case 24:
        memcpy(rule_array + 3 * CCA_KEYWORD_SIZE, "KEYLN24 ", CCA_KEYWORD_SIZE);
        break;
    case 32:
        memcpy(rule_array + 3 * CCA_KEYWORD_SIZE, "KEYLN32 ", CCA_KEYWORD_SIZE);
        break;
    default:
        TRACE_ERROR("Invalid key length: %lu\n", key_size);
        return CKR_KEY_SIZE_RANGE;
    }

    rule_array_count = 4;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBKTB(&return_code, &reason_code,
                    &exit_data_len, exit_data,
                    key_token, key_type,
                    &rule_array_count, rule_array,
                    NULL, reserved_1,
                    NULL, &point_to_array_of_zeros,
                    NULL, NULL, NULL, NULL, mkvp);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBTKB (AES TOKEN BUILD) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    *key_token_size = CCA_KEY_ID_SIZE;

    return CKR_OK;
}

CK_RV token_specific_aes_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **aes_key, CK_ULONG *len,
                                 CK_ULONG key_size, CK_BBOOL *is_opaque)
{
    struct cca_private_data *cca_data = tokdata->private_data;
    CK_ULONG key_token_len;
    unsigned char key_form[CCA_KEYWORD_SIZE];
    unsigned char key_type[CCA_KEYWORD_SIZE];
    CK_IBM_CCA_AES_KEY_MODE_TYPE mode;
    CK_RV rc;

    if (cca_data->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = cca_get_and_set_aes_key_mode(tokdata, tmpl, &mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("cca_get_and_set_aes_key_mode failed\n");
        return rc;
    }

    if (mode == CK_IBM_CCA_AES_CIPHER_KEY)
        key_token_len = CCA_MAX_AES_CIPHER_KEY_SIZE;
    else
        key_token_len = CCA_KEY_ID_SIZE;

    *aes_key = calloc(key_token_len, 1);
    if (*aes_key == NULL)
        return CKR_HOST_MEMORY;
    *len = key_token_len;
    *is_opaque = TRUE;

    if (mode == CK_IBM_CCA_AES_CIPHER_KEY)
        rc = cca_build_aes_cipher_token(tokdata, tmpl,
                                        *aes_key, &key_token_len);
    else
        rc = cca_build_aes_data_token(tokdata, key_size,
                                      *aes_key, &key_token_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build CCA key token");
        /* Caller will free returned aes_key */
        return rc;
    }

    memcpy(key_form, "OP      ", CCA_KEYWORD_SIZE);
    if (mode == CK_IBM_CCA_AES_CIPHER_KEY)
        memcpy(key_type, "TOKEN   ", CCA_KEYWORD_SIZE);
    else
        memcpy(key_type, "AESTOKEN", CCA_KEYWORD_SIZE);

    if (mode == CK_IBM_CCA_AES_CIPHER_KEY)
        return cca_cipher_key_gen(tokdata, tmpl, CCA_AES_KEY, *aes_key, len,
                                  key_form, key_type, key_size, FALSE, NULL);
    else
        return cca_key_gen(tokdata, tmpl, CCA_AES_KEY, *aes_key, key_form,
                           key_type, key_size, FALSE, NULL);
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t * tokdata,
                             SESSION  *session,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE encrypt)
{
    long return_code, reason_code, rule_array_count;
    long block_size = 16;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
    long opt_data_len = 0, key_params_len = 0, exit_data_len = 0, IV_len = 0,
         chain_vector_len = 0;
    unsigned char exit_data[1];
    CK_BYTE *local_out = out_data;
    CK_ATTRIBUTE *attr = NULL;
    long int key_len;
    CK_RV rc;
#ifndef NO_PKEY
    CK_MECHANISM mech = { CKM_AES_ECB, NULL, 0 };
#endif

#ifdef NO_PKEY
    UNUSED(session);
#endif

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }
    key_len = attr->ulValueLen;

#ifndef NO_PKEY
    /* CCA token protected key option */
    rc = ccatok_pkey_check(tokdata, session, key, &mech);
    switch (rc) {
    case CKR_OK:
        rc = pkey_aes_ecb(tokdata, session, key, in_data, in_data_len,
                          out_data, out_data_len, encrypt,
                          ccatok_pkey_convert_key);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        /* fallback */
        break;
    default:
        goto done;
    }
#endif /* NO_PKEY */

    /* Fallback: Perform the function via the CCA card ... */
    rule_array_count = 4;
    memcpy(rule_array, "AES     ECB     KEYIDENTINITIAL ",
           rule_array_count * (size_t) CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        if (encrypt) {
            dll_CSNBSAE(&return_code,
                        &reason_code,
                        &exit_data_len,
                        exit_data,
                        &rule_array_count,
                        rule_array,
                        &key_len,
                        attr->pValue,
                        &key_params_len,
                        NULL,
                        &block_size,
                        &IV_len,
                        NULL,
                        &chain_vector_len,
                        NULL,
                        (long int *)&in_data_len,
                        in_data,
                        (long int *)out_data_len,
                        local_out,
                        &opt_data_len, NULL);
        } else {
            dll_CSNBSAD(&return_code,
                        &reason_code,
                        &exit_data_len,
                        exit_data,
                        &rule_array_count,
                        rule_array,
                        &key_len,
                        attr->pValue,
                        &key_params_len,
                        NULL,
                        &block_size,
                        &IV_len,
                        NULL,
                        &chain_vector_len,
                        NULL,
                        (long int *)&in_data_len,
                        in_data,
                        (long int *)out_data_len,
                        local_out,
                        &opt_data_len,
                        NULL);
        }
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        if (encrypt) {
            TRACE_ERROR("CSNBSAE (AES ENCRYPT) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
        } else {
            TRACE_ERROR("CSNBSAD (AES DECRYPT) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
        }
        (*out_data_len) = 0;
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        if (encrypt) {
            TRACE_WARNING("CSNBSAE (AES ENCRYPT) succeeded, but"
                          " returned reason:%ld\n", reason_code);
        } else {
            TRACE_WARNING("CSNBSAD (AES DECRYPT) succeeded, but"
                          " returned reason:%ld\n", reason_code);
        }
    }

    rc = CKR_OK;

#ifndef NO_PKEY
done:
#endif

    return rc;
}

CK_RV token_specific_aes_cbc(STDLL_TokData_t * tokdata,
                             SESSION  *session,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE * init_v, CK_BYTE encrypt)
{
    long return_code, reason_code, rule_array_count, length;
    long block_size = 16;
    unsigned char chaining_vector[32];
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
    long opt_data_len = 0, key_params_len = 0, exit_data_len = 0, IV_len = 16,
         chain_vector_len = 32;
    CK_BYTE *local_out = out_data;
    unsigned char exit_data[1];
    CK_ATTRIBUTE *attr = NULL;
    long int key_len;
    CK_RV rc;
#ifndef NO_PKEY
    CK_MECHANISM mech = { CKM_AES_CBC, init_v, IV_len };
#endif

#ifdef NO_PKEY
    UNUSED(session);
#endif

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }
    key_len = attr->ulValueLen;

#ifndef NO_PKEY
    /* CCA token protected key option */
    rc = ccatok_pkey_check(tokdata, session, key, &mech);
    switch (rc) {
    case CKR_OK:
        rc = pkey_aes_cbc(tokdata, session, key, init_v, in_data, in_data_len,
                          out_data, out_data_len, encrypt,
                          ccatok_pkey_convert_key);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        /* fallback */
        break;
    default:
        goto done;
    }
#endif /* NO_PKEY */

    /* Fallback: Perform the function via the CCA card ... */
    if (in_data_len % 16 == 0) {
        rule_array_count = 3;
        memcpy(rule_array, "AES     KEYIDENTINITIAL ",
               rule_array_count * (size_t) CCA_KEYWORD_SIZE);
    } else {
        if ((encrypt) && (*out_data_len < (in_data_len + 16))) {
            local_out = malloc(in_data_len + 16);
            if (!local_out) {
                TRACE_ERROR("Malloc of %lu bytes failed.\n", in_data_len + 16);
                return CKR_HOST_MEMORY;
            }
        }

        rule_array_count = 3;
        memcpy(rule_array, "AES     PKCS-PADKEYIDENT",
               rule_array_count * (size_t) CCA_KEYWORD_SIZE);
    }

    length = in_data_len;
    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        if (encrypt) {
            dll_CSNBSAE(&return_code,
                        &reason_code,
                        &exit_data_len,
                        exit_data,
                        &rule_array_count,
                        rule_array,
                        &key_len,
                        attr->pValue,
                        &key_params_len,
                        exit_data,
                        &block_size,
                        &IV_len,
                        init_v,
                        &chain_vector_len,
                        chaining_vector,
                        &length,
                        in_data,
                        (long int *)out_data_len,
                        local_out,
                        &opt_data_len,
                        NULL);
        } else {
            dll_CSNBSAD(&return_code,
                        &reason_code,
                        &exit_data_len,
                        exit_data,
                        &rule_array_count,
                        rule_array,
                        &key_len,
                        attr->pValue,
                        &key_params_len,
                        NULL,
                        &block_size,
                        &IV_len,
                        init_v,
                        &chain_vector_len,
                        chaining_vector,
                        &length,
                        in_data,
                        (long int *)out_data_len,
                        local_out,
                        &opt_data_len,
                        NULL);
        }
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        if (encrypt) {
            TRACE_ERROR("CSNBSAE (AES ENCRYPT) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
        } else {
            TRACE_ERROR("CSNBSAD (AES DECRYPT) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
        }
        (*out_data_len) = 0;
        if (local_out != out_data)
            free(local_out);
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        if (encrypt) {
            TRACE_WARNING("CSNBSAE (AES ENCRYPT) succeeded, but"
                          " returned reason:%ld\n", reason_code);
        } else {
            TRACE_WARNING("CSNBSAD (AES DECRYPT) succeeded, but"
                          " returned reason:%ld\n", reason_code);
        }
    }

    /* If we malloc'd a new buffer due to overflow concerns and the data
     * coming out turned out to be bigger than expected, return an error.
     *
     * Else, memcpy the data back to the user's buffer
     */
    if ((local_out != out_data) && ((CK_ULONG) length > *out_data_len)) {
        TRACE_ERROR("buffer too small: %ld bytes to write into %ld "
                    "bytes space\n", length, *out_data_len);
        free(local_out);
        return CKR_BUFFER_TOO_SMALL;
    } else if (local_out != out_data) {
        memcpy(out_data, local_out, (size_t) length);
        free(local_out);
    }

    *out_data_len = length;

    rc = CKR_OK;

#ifndef NO_PKEY
done:
#endif

    return rc;
}

static CK_BBOOL token_specific_filter_mechanism(STDLL_TokData_t *tokdata,
                                                CK_MECHANISM_TYPE mechanism)
{
    CK_BBOOL rc = CK_FALSE;

    switch(mechanism) {
    case CKM_AES_XTS:
    case CKM_AES_XTS_KEY_GEN:
#ifndef NO_PKEY
        if (ccatok_pkey_option_disabled(tokdata) ||
            !((struct cca_private_data *)tokdata->private_data)->pkey_wrap_supported) {
            TRACE_ERROR("AES XTS Mech not supported\n");
            rc = CK_FALSE;
            break;
        }
        rc = CK_TRUE;
#else
        UNUSED(tokdata);
        rc = CK_FALSE;
#endif
        break;
    case CKM_IBM_DILITHIUM:
        /* Enable the mechanism if at least Dilithium Round 2 65 is supported */
        rc = cca_pqc_strength_supported(tokdata, mechanism,
                                        CK_IBM_DILITHIUM_KEYFORM_ROUND2_65);
        break;
    case CKM_SHA3_224:
    case CKM_SHA3_256:
    case CKM_SHA3_384:
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
    case CKM_SHA3_224_RSA_PKCS:
    case CKM_SHA3_256_RSA_PKCS:
    case CKM_SHA3_384_RSA_PKCS:
    case CKM_SHA3_512_RSA_PKCS:
    case CKM_ECDSA_SHA3_224:
    case CKM_ECDSA_SHA3_256:
    case CKM_ECDSA_SHA3_384:
    case CKM_ECDSA_SHA3_512:
        rc = cca_sha3_supported(tokdata);
        break;
    case CKM_RSA_AES_KEY_WRAP:
        rc = cca_rsa_aeskw_supported(tokdata, -1);
        break;
    default:
        rc = CK_TRUE;
        break;
    }
    return rc;
}

/* See the top of this file for the declarations of mech_list and
 * mech_list_len.
 */
CK_RV token_specific_get_mechanism_list(STDLL_TokData_t * tokdata,
                                        CK_MECHANISM_TYPE * pMechanismList,
                                        CK_ULONG * pulCount)
{
    return ock_generic_get_mechanism_list(tokdata, pMechanismList, pulCount,
                                          &token_specific_filter_mechanism);
}

CK_RV token_specific_get_mechanism_info(STDLL_TokData_t * tokdata,
                                        CK_MECHANISM_TYPE type,
                                        CK_MECHANISM_INFO * pInfo)
{
    return ock_generic_get_mechanism_info(tokdata, type, pInfo,
                                          &token_specific_filter_mechanism);
}

CK_BBOOL is_curve_error(long return_code, long reason_code)
{
    if (return_code == 8) {
        /*
         * The following reason codes denote that the curve is not supported
         *  8 874 (36A)    Error in Cert processing. Elliptic Curve is not
         *                 supported.
         *  8 2158 (86E)   There is a mismatch between ECC key tokens of curve
         *                 types, key lengths, or both. Curve types and key
         *                 lengths must match.
         *  8 6015 (177F)  An ECC curve type is invalid or its usage is
         *                 inconsistent.
         *  8 6017 (1781)  Curve size p is invalid or its usage is inconsistent.
         */
        switch (reason_code) {
        case 874:
        case 2158:
        case 6015:
        case 6017:
            return TRUE;
        }
    }
    return FALSE;
}

static CK_RV curve_supported(STDLL_TokData_t *tokdata,
                             TEMPLATE *templ, uint8_t *curve_type,
                             uint16_t *curve_bitlen, int *curve_nid)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    const struct cca_version cca_v7_2 = { .ver = 7, .rel = 2, .mod = 0 };
    CK_ATTRIBUTE *attr = NULL;
    unsigned int i;
    int ret;
    CK_RV rc;

    /* Check if curve supported */
    rc = template_attribute_get_non_empty(templ, CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the key.\n");
        return rc;
    }

    for (i = 0; i < NUMEC; i++) {
        if ((attr->ulValueLen == der_ec_supported[i].data_size) &&
            (memcmp(attr->pValue, der_ec_supported[i].data,
                    attr->ulValueLen) == 0) &&
            (der_ec_supported[i].curve_type == PRIME_CURVE ||
             der_ec_supported[i].curve_type == KOBLITZ_CURVE ||
             der_ec_supported[i].curve_type == BRAINPOOL_CURVE) &&
             der_ec_supported[i].twisted == CK_FALSE) {

            if (der_ec_supported[i].curve_type == KOBLITZ_CURVE) {
                /*
                 * The Koblitz curve is only supported if all configured CCA
                 * adapters have firmware version 7.2 or later, and if the CCA
                 * host library has version 7.2 or later.
                 */
                if (pthread_rwlock_rdlock(&cca_private->min_card_version_rwlock)
                                                                    != 0) {
                    TRACE_ERROR("CCA min_card_version RD-Lock failed.\n");
                    return CKR_CANT_LOCK;
                }

                ret = compare_cca_version(&cca_private->min_card_version,
                                          &cca_v7_2);

                if (pthread_rwlock_unlock(&cca_private->min_card_version_rwlock)
                                                                    != 0) {
                    TRACE_ERROR("CCA min_card_version RD-Unlock failed.\n");
                    return CKR_CANT_LOCK;
                }

                if (ret < 0 ||
                    compare_cca_version(&cca_private->cca_lib_version,
                                        &cca_v7_2) < 0 ) {
                    TRACE_DEVEL("Koblitz curve is only supported by CCA "
                                "version 7.2 or later\n");
                    return CKR_CURVE_NOT_SUPPORTED;
                }
            }

            *curve_type = der_ec_supported[i].curve_type;
            *curve_bitlen = der_ec_supported[i].len_bits;
            *curve_nid = der_ec_supported[i].nid;
            return CKR_OK;
        }
    }

    return CKR_CURVE_NOT_SUPPORTED;
}

uint16_t cca_ec_privkey_offset(CK_BYTE * tok)
{
    uint8_t privkey_id = CCA_PRIVKEY_ID, privkey_rec;
    privkey_rec = *(uint8_t *)&tok[CCA_EC_HEADER_SIZE];

    if ((memcmp(&privkey_rec, &privkey_id, sizeof(uint8_t)) == 0)) {
        return CCA_EC_HEADER_SIZE;
    }
    TRACE_WARNING("+++++++++ Token key private section is CORRUPTED\n");

    return CCA_EC_HEADER_SIZE;
}

uint16_t cca_ec_publkey_offset(CK_BYTE * tok)
{
    uint16_t priv_offset, privSec_len;
    uint8_t publkey_id = CCA_PUBLKEY_ID, publkey_rec;

    priv_offset = cca_ec_privkey_offset(tok);
    privSec_len =
        be16toh(*(uint16_t *)&tok[priv_offset + CCA_SECTION_LEN_OFFSET]);
    publkey_rec = *(uint8_t *)&tok[priv_offset + privSec_len];

    if ((memcmp(&publkey_rec, &publkey_id, sizeof(uint8_t)) == 0)) {
        return (priv_offset + privSec_len);
    }
    TRACE_WARNING("++++++++ Token key public section is CORRUPTED\n");

    return (priv_offset + privSec_len);
}

struct cca_key_derivation_data *cca_ec_ecc_key_derivation_info(CK_BYTE *tok)
{
    uint16_t pub_offset, pubsec_len, tok_len, ecc_offset;
    struct cca_key_derivation_data *eccinfo;

    tok_len = be16toh(*(uint16_t *)&tok[CCA_SECTION_LEN_OFFSET]);

    pub_offset = cca_ec_publkey_offset(tok);
    pubsec_len =
        be16toh(*(uint16_t *)&tok[pub_offset + CCA_SECTION_LEN_OFFSET]);

    ecc_offset = pub_offset + pubsec_len;
    if (ecc_offset >= tok_len)
        return NULL;

    if (tok[ecc_offset] != CCA_ECCDERIVEINFO_ID)
        return NULL;

    eccinfo = (struct cca_key_derivation_data *)
                    (&tok[ecc_offset] + CCA_SECTION_HEADER_LEN);
    return eccinfo;
}

CK_RV token_create_ec_keypair(TEMPLATE * publ_tmpl,
                              TEMPLATE * priv_tmpl,
                              CK_ULONG priv_tok_len, CK_BYTE *priv_tok,
                              CK_ULONG publ_tok_len, CK_BYTE *publ_tok)
{
    uint16_t pubkey_offset, qlen_offset, q_offset;
    CK_ULONG q_len;
    CK_BYTE q[CCATOK_EC_MAX_Q_LEN];
    CK_RV rv;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len;

    /*
     * The token includes the header section first,
     * the private key section in the middle,
     * and the public key section last.
     */

    /* The pkcs#11v2.20:
     * CKA_ECDSA_PARAMS must be in public key's template when
     * generating key pair and added to private key template.
     * CKA_EC_POINT added to public key when key is generated.
     */

    /*
     * Get Q data for public key.
     */
    pubkey_offset = cca_ec_publkey_offset(priv_tok);

    qlen_offset = pubkey_offset + CCA_EC_INTTOK_PUBKEY_Q_LEN_OFFSET;
    q_len = *(uint16_t *) & priv_tok[qlen_offset];
    q_len = be16toh(q_len);

    if (q_len > CCATOK_EC_MAX_Q_LEN) {
        TRACE_ERROR("Not enough room to return q. (Got %d, need %ld)\n",
                    CCATOK_EC_MAX_Q_LEN, q_len);
        return CKR_FUNCTION_FAILED;
    }

    q_offset = pubkey_offset + CCA_EC_INTTOK_PUBKEY_Q_OFFSET;
    memcpy(q, &priv_tok[q_offset], (size_t) q_len);

    rv = ber_encode_OCTET_STRING(FALSE, &ecpoint, &ecpoint_len, q, q_len);
    if (rv != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
        return rv;
    }

    if ((rv = build_update_attribute(publ_tmpl, CKA_EC_POINT,
                                     ecpoint, ecpoint_len))) {
        TRACE_DEVEL("build_update_attribute for q failed rv=0x%lx\n", rv);
        free(ecpoint);
        return rv;
    }
    free(ecpoint);

    /* Add ec params to private key */
    rv = template_attribute_get_non_empty(publ_tmpl, CKA_ECDSA_PARAMS, &attr);
    if (rv != CKR_OK) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the key.\n");
        return rv;
    }

    if ((rv = build_update_attribute(priv_tmpl, CKA_ECDSA_PARAMS,
                                     attr->pValue, attr->ulValueLen))) {
        TRACE_DEVEL("build_update_attribute for der data failed "
                    "rv=0x%lx\n", rv);
        return rv;
    }

    /* store publ key token into CKA_IBM_OPAQUE of the public key object */
    if ((rv = build_update_attribute(publ_tmpl, CKA_IBM_OPAQUE,
                                     publ_tok, publ_tok_len))) {
        TRACE_DEVEL("build_update_attribute for publ_tok failed rv=0x%lx\n", rv);
        return rv;
    }

    /* store priv key token into CKA_IBM_OPAQUE of the private key object */
    if ((rv = build_update_attribute(priv_tmpl, CKA_IBM_OPAQUE,
                                     priv_tok, priv_tok_len))) {
        TRACE_DEVEL("build_update_attribute for priv_tok failed rv=0x%lx\n", rv);
        return rv;
    }

    return CKR_OK;
}

static CK_RV ccatok_get_key_info_from_derive_template(TEMPLATE *priv_tmpl,
                                                      CK_KEY_TYPE *key_type,
                                                      CK_ULONG *value_len,
                                      CK_IBM_CCA_AES_KEY_MODE_TYPE *key_mode)
{
    CK_ATTRIBUTE *derive_tmpl_attr = NULL;
    CK_RV rv;

    *key_type = (CK_ULONG)-1;
    *value_len = 0;
    *key_mode = (CK_ULONG)-1;

    if (template_attribute_find(priv_tmpl, CKA_DERIVE_TEMPLATE,
                                &derive_tmpl_attr) != TRUE)
        return CKR_OK;

    rv = get_ulong_attribute_by_type((CK_ATTRIBUTE_PTR)derive_tmpl_attr->pValue,
                                     derive_tmpl_attr->ulValueLen /
                                                         sizeof(CK_ATTRIBUTE),
                                     CKA_KEY_TYPE, key_type);
    if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE)
        return rv;

    rv = get_ulong_attribute_by_type((CK_ATTRIBUTE_PTR)derive_tmpl_attr->pValue,
                                     derive_tmpl_attr->ulValueLen /
                                                sizeof(CK_ATTRIBUTE),
                                     CKA_VALUE_LEN, value_len);
    if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE)
        return rv;

    rv = get_ulong_attribute_by_type((CK_ATTRIBUTE_PTR)derive_tmpl_attr->pValue,
                                     derive_tmpl_attr->ulValueLen /
                                                sizeof(CK_ATTRIBUTE),
                                     CKA_IBM_CCA_AES_KEY_MODE, key_mode);
    if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE)
        return rv;

    return CKR_OK;
}

/*
 * Try to get derive key type and size for CKA_DERIVE_TEMPLATE.
 * If CKA_DERIVE_TEMPLATE is not available, or it does not contain attribute
 * CKA_KEY_TYPE, then the default is AES-256.
 * If CKA_KEY_TYPE is contained and is CKK_AES, it also checks if attribute
 * CKA_VALUE_LEN is contained and specifies a valid AES key size.
 * If CKA_IBM_CCA_AES_KEY_MODE is contained, it determines the CCA key mode,
 * otherwise the global default from the CCA config file is used.
 * The CCA token only supports to derive AES keys.
 */
static CK_RV ccatok_build_ec_derive_info(STDLL_TokData_t *tokdata,
                                         TEMPLATE *priv_tmpl,
                                         struct cca_key_derivation_data
                                                                 *derive_info)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    CK_IBM_CCA_AES_KEY_MODE_TYPE key_mode;
    CK_KEY_TYPE key_type;
    CK_ULONG value_len;
    CK_RV rv;

    /* Defaults: AES-256, DATA or CIPHER as per global setting */
    switch (cca_private->aes_key_mode) {
    case AES_KEY_MODE_DATA:
        derive_info->key_type = CCA_KEY_DERIVE_TYPE_DATA;
        break;
    case AES_KEY_MODE_CIPHER:
        derive_info->key_type = CCA_KEY_DERIVE_TYPE_CIPHER;
        break;
    default:
        TRACE_DEVEL("Invalid AES key mode: %d\n", cca_private->aes_key_mode);
        return CKR_FUNCTION_FAILED;
    }

    derive_info->key_algorithm = CCA_AES_KEY;
    derive_info->key_size = 256;

    rv = ccatok_get_key_info_from_derive_template(priv_tmpl,
                                                  &key_type, &value_len,
                                                  &key_mode);
    if (rv != CKR_OK)
        return rv;

    switch (key_mode) {
    case CK_IBM_CCA_AES_DATA_KEY:
        derive_info->key_type = CCA_KEY_DERIVE_TYPE_DATA;
        break;
    case CK_IBM_CCA_AES_CIPHER_KEY:
        derive_info->key_type = CCA_KEY_DERIVE_TYPE_CIPHER;
        break;
    default:
        /* Use global default as set above */
        break;
    }

    if (key_type == (CK_ULONG)-1)
        return CKR_OK;

    switch (key_type) {
    case CKK_AES:
       switch (value_len) {
        case 0:
            derive_info->key_size = 256; /* Default to AES-256 */
            break;
        case AES_KEY_SIZE_128:
        case AES_KEY_SIZE_192:
        case AES_KEY_SIZE_256:
            derive_info->key_size = value_len * 8;
            break;
        default:
            TRACE_ERROR("Unsupported AES key size %lu\n", value_len);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
    default:
        TRACE_ERROR("CCA does not support to derive keys of type 0x%lx as "
                    "DATA keys\n", key_type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

static CK_RV ccatok_check_ec_derive_info(STDLL_TokData_t *tokdata, OBJECT *obj,
                                         TEMPLATE *new_tmpl)
{
    CK_ATTRIBUTE *opaque_attr, *derive_tmpl_attr = NULL;
    CK_IBM_CCA_AES_KEY_MODE_TYPE derive_key_mode;
    CK_KEY_TYPE derive_key_type;
    CK_ULONG derive_value_len;
    CK_BBOOL derive = FALSE;
    struct cca_key_derivation_data *ecc_info;
    CK_RV rc;

    UNUSED(tokdata);

    rc = template_attribute_get_non_empty(obj->template,
                                          CKA_IBM_OPAQUE, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    ecc_info = cca_ec_ecc_key_derivation_info(opaque_attr->pValue);

    rc = template_attribute_get_bool(new_tmpl, CKA_DERIVE, &derive);
    if (rc == CKR_OK && derive == TRUE) {
        /*
         * CKA_DERIVE of an ECC private key is set to TRUE.
         * Check if the key has an ECC key derivation section (X'23').
         * This is required to be able to support ECDH key derivation.
         */
        if (ecc_info == NULL) {
            TRACE_ERROR("ECC private key does not have an ECC key derivation "
                        "info section X'23'\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (ecc_info->key_type != CCA_KEY_DERIVE_TYPE_DATA &&
            ecc_info->key_type != CCA_KEY_DERIVE_TYPE_CIPHER &&
            ecc_info->key_algorithm != CCA_AES_KEY) {
            TRACE_ERROR("CCA can not derive keys other than AES DATA or "
                        "AES CIPHER key tokens\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if (template_attribute_find(new_tmpl, CKA_DERIVE_TEMPLATE,
                                &derive_tmpl_attr)) {
        /*
         * CKA_DERIVE_TEMPLATE is changed.
         * Check if the key has an ECC key derivation section (X'23'),
         * and if it matches the CKA_KEY_TYPE, CKA_VALUE_LEN and
         * CKA_IBM_CCA_AES_KEY_MODE attributes in the derive template.
         */
        rc = ccatok_get_key_info_from_derive_template(new_tmpl,
                                                      &derive_key_type,
                                                      &derive_value_len,
                                                      &derive_key_mode);
        if (rc == CKR_OK && ecc_info != NULL) {
            switch (derive_key_type) {
            case (CK_ULONG)-1:
            case CKK_AES:
                if (ecc_info->key_algorithm != CCA_AES_KEY) {
                    TRACE_ERROR("The EC private key can not derive keys "
                                "other than AES keys\n");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                /* Also check key size, if specified in template */
                if (derive_value_len != 0 &&
                    derive_value_len * 8 != ecc_info->key_size) {
                    TRACE_ERROR("The EC private key can not derive keys "
                                "other than AES-%u keys\n",
                                ecc_info->key_size);
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                break;
            default:
                TRACE_ERROR("CCA does not support to derive keys of type "
                            "0x%lx\n", derive_key_type);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }

            switch (derive_key_mode) {
            case (CK_ULONG)-1:
                if (ecc_info->key_type != CCA_KEY_DERIVE_TYPE_DATA &&
                    ecc_info->key_type != CCA_KEY_DERIVE_TYPE_CIPHER) {
                    TRACE_ERROR("The EC private key can not derive keys "
                                "other than AES DATA or AES CIPHER keys\n");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                break;
            case CK_IBM_CCA_AES_DATA_KEY:
                if (ecc_info->key_type != CCA_KEY_DERIVE_TYPE_DATA) {
                    TRACE_ERROR("The EC private key can not derive keys "
                                "other than AES DATA keys\n");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                break;
            case CK_IBM_CCA_AES_CIPHER_KEY:
                if (ecc_info->key_type != CCA_KEY_DERIVE_TYPE_CIPHER) {
                    TRACE_ERROR("The EC private key can not derive keys "
                                "other than AES CIPHER keys\n");
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                break;
            default:
                TRACE_ERROR("CCA does not support to derive keys of mode "
                            "0x%lx\n", derive_key_mode);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }
    }

    return CKR_OK;
}


CK_RV token_specific_ec_generate_keypair(STDLL_TokData_t * tokdata,
                                         TEMPLATE * publ_tmpl,
                                         TEMPLATE * priv_tmpl)
{
    long return_code, reason_code, rule_array_count, exit_data_len = 0;
    unsigned char *exit_data = NULL;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long key_value_structure_length, private_key_name_length, key_token_length;
    unsigned char key_value_structure[CCA_EC_KEY_VALUE_STRUCT_SIZE] = { 0, };
    unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
    unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    long regeneration_data_length;
    long priv_key_token_length, publ_key_token_length;
    unsigned char regeneration_data[CCA_REGENERATION_DATA_SIZE] = { 0, };
    unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
    unsigned char priv_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    unsigned char publ_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    struct cca_key_derivation_data deriv_data;
    long deriv_data_size;
    CK_RV rv;
    long param1 = 0;
    unsigned char *param2 = NULL;
    uint8_t curve_type;
    uint16_t curve_bitlen, be_curve_bitlen;
    int curve_nid;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rv = curve_supported(tokdata, publ_tmpl, &curve_type, &curve_bitlen,
                         &curve_nid);
    if (rv != CKR_OK) {
        TRACE_ERROR("Curve not supported\n");
        return rv;
    }

    /*
     * See CCA doc: page 94 for offset of data in key_value_structure
     */
    memcpy(key_value_structure,
           &curve_type, sizeof(uint8_t));
    be_curve_bitlen = be16toh(curve_bitlen);
    memcpy(&key_value_structure[CCA_PKB_EC_LEN_OFFSET],
           &be_curve_bitlen, sizeof(uint16_t));

    key_value_structure_length = CCA_EC_KEY_VALUE_STRUCT_SIZE;

    /* Enable ECDH key derivation with keys generated by the CCA token */
    rule_array_count = 3;
    memcpy(rule_array, "ECC-PAIRKEY-MGMTECC-VER1", 3 * CCA_KEYWORD_SIZE);

#ifndef NO_PKEY
    /* Add protected key related attributes to the rule array */
    rv = ccatok_pkey_add_attrs(tokdata, priv_tmpl, CKK_EC, curve_type,
                               curve_bitlen, 0, rule_array, sizeof(rule_array),
                               (CK_ULONG *)&rule_array_count);
    if (rv != CKR_OK) {
        TRACE_ERROR("%s ccatok_pkey_add_attrs failed with rc=0x%lx\n", __func__, rv);
        return rv;
    }
#endif /* NO_PKEY */

    private_key_name_length = 0;

    /* Enable the ECC private key to derive keys */
    rv = ccatok_build_ec_derive_info(tokdata, priv_tmpl, &deriv_data);
    if (rv != CKR_OK) {
        TRACE_ERROR("%s ccatok_build_derive_info failed with rc=0x%lx\n",
                    __func__, rv);
        return rv;
    }

    deriv_data_size = sizeof(deriv_data);
    key_token_length = CCA_KEY_TOKEN_SIZE;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKB(&return_code,
                    &reason_code,
                    &exit_data_len,
                    exit_data,
                    &rule_array_count,
                    rule_array,
                    &key_value_structure_length,
                    key_value_structure,
                    &private_key_name_length,
                    private_key_name,
                    &param1,
                    param2,
                    &deriv_data_size,
                    (unsigned char *)&deriv_data,
                    &param1,
                    param2,
                    &param1, param2,
                    &param1, param2, &key_token_length, key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKB (EC KEY TOKEN BUILD) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        if (is_curve_error(return_code, reason_code))
            return CKR_CURVE_NOT_SUPPORTED;
        return CKR_FUNCTION_FAILED;
    }

    rule_array_count = 1;
    memset(rule_array, 0, sizeof(rule_array));
    memcpy(rule_array, "MASTER  ", (size_t) CCA_KEYWORD_SIZE);

    priv_key_token_length = CCA_KEY_TOKEN_SIZE;

    regeneration_data_length = 0;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKG(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    &regeneration_data_length,
                    regeneration_data,
                    &key_token_length,
                    key_token,
                    transport_key_identifier,
                    &priv_key_token_length, priv_key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKG (EC KEY GENERATE) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        if (is_curve_error(return_code, reason_code))
            return CKR_CURVE_NOT_SUPPORTED;
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(priv_key_token, priv_key_token_length,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been generated\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rv = cca_reencipher_created_key(tokdata, priv_tmpl, priv_key_token,
                                    priv_key_token_length, new_mk, keytype,
                                    FALSE);
    if (rv != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rv);
        return rv;
    }

    TRACE_DEVEL("ECC secure private key token generated. size: %ld\n",
                priv_key_token_length);

    rule_array_count = 0;
    publ_key_token_length = CCA_KEY_TOKEN_SIZE;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKX(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    &priv_key_token_length, priv_key_token,
                    &publ_key_token_length, publ_key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKX (PUBLIC KEY TOKEN EXTRACT) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    TRACE_DEVEL("ECC secure public key token generated. size: %ld\n",
                publ_key_token_length);

    rv = token_create_ec_keypair(publ_tmpl, priv_tmpl,
                                 priv_key_token_length, priv_key_token,
                                 publ_key_token_length, publ_key_token);
    if (rv != CKR_OK) {
        TRACE_DEVEL("token_create_ec_keypair failed. rv: %lu\n", rv);
        return rv;
    }

    TRACE_DEBUG("%s: priv template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(priv_tmpl);
    TRACE_DEBUG("%s: publ template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(publ_tmpl);

    return rv;
}

CK_RV token_specific_ec_sign(STDLL_TokData_t * tokdata,
                             SESSION * sess,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len, OBJECT * key_obj)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long signature_bit_length;
    CK_ATTRIBUTE *attr;
    CK_RV rc;
#ifndef NO_PKEY
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
#endif

#ifdef NO_PKEY
    UNUSED(sess);
#endif

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

#ifndef NO_PKEY
    /* CCA token protected key option: perform the function via CPACF */
    rc = ccatok_pkey_check(tokdata, sess, key_obj, &mech);
    switch (rc) {
    case CKR_OK:
        rc = pkey_ec_sign(tokdata, sess, key_obj, in_data, in_data_len,
                          out_data, out_data_len, NULL,
                          ccatok_pkey_convert_key);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        /* fallback */
        break;
    default:
        goto done;
    }
#endif /* NO_PKEY */

    /* Fallback: Perform the function via the CCA card */
    rule_array_count = 1;
    memcpy(rule_array, "ECDSA   ", CCA_KEYWORD_SIZE);
    *out_data_len = *out_data_len > 132 ? 132 : *out_data_len;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSG(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *) &(attr->ulValueLen),
                    attr->pValue,
                    (long *) &in_data_len,
                    in_data,
                    (long *) out_data_len, &signature_bit_length, out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSG (EC SIGN) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        if (is_curve_error(return_code, reason_code))
            return CKR_CURVE_NOT_SUPPORTED;
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDDSG (EC SIGN) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }

    rc = CKR_OK;

#ifndef NO_PKEY
done:
#endif

    return rc;
}

CK_RV token_specific_ec_verify(STDLL_TokData_t * tokdata,
                               SESSION * sess,
                               CK_BYTE * in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE * out_data,
                               CK_ULONG out_data_len, OBJECT * key_obj)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    CK_RV rc;
#ifndef NO_PKEY
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
#endif

#ifdef NO_PKEY
    UNUSED(sess);
#endif

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

#ifndef NO_PKEY
    /* CCA token protected key option: perform the function via CPACF */
    rc = ccatok_pkey_check(tokdata, sess, key_obj, &mech);
    switch (rc) {
    case CKR_OK:
        rc = pkey_ec_verify(key_obj, in_data, in_data_len,
                            out_data, out_data_len);
        goto done;
    case CKR_FUNCTION_NOT_SUPPORTED:
        /* fallback */
        break;
    default:
        goto done;
    }
#endif /* NO_PKEY */

    /* Fallback: Perform the function via the CCA card */
    rule_array_count = 1;
    memcpy(rule_array, "ECDSA   ", CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSV(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *) &(attr->ulValueLen),
                    attr->pValue,
                    (long *) &in_data_len,
                    in_data, (long *) &out_data_len, out_data);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code == 4 && reason_code == 429) {
        return CKR_SIGNATURE_INVALID;
    } else if (return_code == 12 && reason_code == 769) {
        return CKR_SIGNATURE_INVALID;
    } else if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSV (EC VERIFY) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        if (is_curve_error(return_code, reason_code))
            return CKR_CURVE_NOT_SUPPORTED;
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDDSV (EC VERIFY) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }

    rc = CKR_OK;

#ifndef NO_PKEY
done:
#endif

    return rc;
}

static CK_BBOOL cca_is_sha3_mech(CK_MECHANISM *mech)
{
    switch (mech->mechanism) {
    case CKM_SHA3_224:
    case CKM_SHA3_256:
    case CKM_SHA3_384:
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
    case CKM_SHA3_224_RSA_PKCS:
    case CKM_SHA3_256_RSA_PKCS:
    case CKM_SHA3_384_RSA_PKCS:
    case CKM_SHA3_512_RSA_PKCS:
    case CKM_ECDSA_SHA3_224:
    case CKM_ECDSA_SHA3_256:
    case CKM_ECDSA_SHA3_384:
    case CKM_ECDSA_SHA3_512:
        return CK_TRUE;
    default:
        return CK_FALSE;
    }
}

CK_RV token_specific_sha_init(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * ctx,
                              CK_MECHANISM * mech)
{
    CK_ULONG hash_size;
    struct cca_sha_ctx *cca_ctx;
    CK_RV rc;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = get_sha_size(mech->mechanism, &hash_size);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_sha_size failed\n");
        return rc;
    }

    if (cca_is_sha3_mech(mech) && !cca_sha3_supported(tokdata)) {
        TRACE_ERROR("SHA-3 mechanism is not supported due to CCA version\n");
        return CKR_MECHANISM_INVALID;
    }

    ctx->context = calloc(1, sizeof(struct cca_sha_ctx));
    if (ctx->context == NULL) {
        TRACE_ERROR("malloc failed in sha digest init\n");
        return CKR_HOST_MEMORY;
    }
    ctx->context_len = sizeof(struct cca_sha_ctx);

    cca_ctx = (struct cca_sha_ctx *) ctx->context;
    cca_ctx->chain_vector_len = cca_is_sha3_mech(mech) ?
                            CCA_CHAIN_VECTOR_SHA3_LEN : CCA_CHAIN_VECTOR_LEN;
    cca_ctx->hash_len = hash_size;
    /* tail_len is already 0 */

    return CKR_OK;
}

CK_RV token_specific_sha(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * ctx,
                         CK_BYTE * in_data, CK_ULONG in_data_len,
                         CK_BYTE * out_data, CK_ULONG * out_data_len)
{
    struct cca_sha_ctx *cca_ctx;
    long return_code, reason_code, rule_array_count = 2;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data || !out_data)
        return CKR_ARGUMENTS_BAD;

    cca_ctx = (struct cca_sha_ctx *) ctx->context;

    if (*out_data_len < (CK_ULONG)cca_ctx->hash_len)
        return CKR_BUFFER_TOO_SMALL;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        memcpy(rule_array, "SHA-1   ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA224:
        memcpy(rule_array, "SHA-224 ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA256:
        memcpy(rule_array, "SHA-256 ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA384:
        memcpy(rule_array, "SHA-384 ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA512:
        memcpy(rule_array, "SHA-512 ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        memcpy(rule_array, "SHA3-224ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        memcpy(rule_array, "SHA3-256ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        memcpy(rule_array, "SHA3-384ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        memcpy(rule_array, "SHA3-512ONLY    ", CCA_KEYWORD_SIZE * 2);
        cca_ctx->part = CCA_HASH_PART_ONLY;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (cca_is_sha3_mech(&ctx->mech) && !cca_sha3_supported(tokdata)) {
        TRACE_ERROR("SHA-3 mechanism is not supported due to CCA version\n");
        return CKR_MECHANISM_INVALID;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBOWH(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                    rule_array, (long int *)&in_data_len, in_data,
                    &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                    &cca_ctx->hash_len, cca_ctx->hash);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBOWH failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(out_data, cca_ctx->hash, cca_ctx->hash_len);
    *out_data_len = cca_ctx->hash_len;

    /* ctx->context should get freed in digest_mgr_cleanup() */
    return CKR_OK;
}

CK_RV token_specific_sha_update(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * ctx,
                                CK_BYTE * in_data, CK_ULONG in_data_len)
{
    struct cca_sha_ctx *cca_ctx;
    long return_code, reason_code, total, buffer_len, rule_array_count = 2;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_RV rc = CKR_OK;
    unsigned char *buffer = NULL;
    CK_ULONG blocksz;
    int use_buffer = 0;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!in_data)
        return CKR_ARGUMENTS_BAD;

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    rc = get_sha_block_size(ctx->mech.mechanism, &blocksz);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_sha_block_size failed\n");
        return rc;
    }

    if (cca_is_sha3_mech(&ctx->mech) && !cca_sha3_supported(tokdata)) {
        TRACE_ERROR("SHA-3 mechanism is not supported due to CCA version\n");
        return CKR_MECHANISM_INVALID;
    }

    cca_ctx = (struct cca_sha_ctx *) ctx->context;

    /* just send if input a multiple of block size and
     * cca_ctx-> tail is empty.
     */
    if ((cca_ctx->tail_len == 0) && ((in_data_len % blocksz) == 0))
        goto send;

    /* at this point, in_data is not multiple of blocksize
     * and/or there is saved data from previous update still
     * needing to be processed
     */

    /* get totals */
    total = cca_ctx->tail_len + in_data_len;

    /* see if we have enough to fill a block */
    if (total >= (long)blocksz) {
        int remainder;

        remainder = total % blocksz;
        buffer_len = total - remainder;

        /* allocate a buffer for sending... */
        if (!(buffer = malloc(buffer_len))) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        memcpy(buffer, cca_ctx->tail, cca_ctx->tail_len);
        memcpy(buffer + cca_ctx->tail_len, in_data, in_data_len - remainder);
        use_buffer = 1;

        /* save remainder data for next time */
        if (remainder)
            memcpy(cca_ctx->tail,
                   in_data + (in_data_len - remainder), remainder);
        cca_ctx->tail_len = remainder;

    } else {
        /* not enough to fill a block, save off data for next round */
        memcpy(cca_ctx->tail + cca_ctx->tail_len, in_data, in_data_len);
        cca_ctx->tail_len += in_data_len;
        return CKR_OK;
    }

send:
    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-1   FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA-1   MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA224:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-224 FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA-224 MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA256:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-256 FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA-256 MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA384:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-384 FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA-384 MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA512:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-512 FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA-512 MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-224FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA3-224MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-256FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA3-256MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-384FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA3-384MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-512FIRST   ", CCA_KEYWORD_SIZE * 2);
            cca_ctx->part = CCA_HASH_PART_MIDDLE;
        } else {
            memcpy(rule_array, "SHA3-512MIDDLE  ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBOWH(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                    rule_array, use_buffer ? &buffer_len : (long *) &in_data_len,
                    use_buffer ? buffer : in_data, &cca_ctx->chain_vector_len,
                    cca_ctx->chain_vector, &cca_ctx->hash_len, cca_ctx->hash);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBOWH (SHA UPDATE) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        rc = CKR_FUNCTION_FAILED;
    }

done:
    if (buffer)
        free(buffer);
    return rc;
}

CK_RV token_specific_sha_final(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * ctx,
                               CK_BYTE * out_data, CK_ULONG * out_data_len)
{
    struct cca_sha_ctx *cca_ctx;
    long return_code, reason_code, rule_array_count = 2;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    cca_ctx = (struct cca_sha_ctx *) ctx->context;
    if (*out_data_len < (CK_ULONG)cca_ctx->hash_len) {
        TRACE_ERROR("out buf too small for hash: %lu\n", *out_data_len);
        return CKR_BUFFER_TOO_SMALL;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-1   ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA-1   LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA224:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-224 ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA-224 LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA256:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-256 ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA-256 LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA384:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-384 ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA-384 LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA512:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA-512 ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA-512 LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-224ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA3-224LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-256ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA3-256LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-384ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA3-384LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        if (cca_ctx->part == CCA_HASH_PART_FIRST) {
            memcpy(rule_array, "SHA3-512ONLY    ", CCA_KEYWORD_SIZE * 2);
        } else {
            /* there's some extra data we need to hash to
             * complete the operation
             */
            memcpy(rule_array, "SHA3-512LAST    ", CCA_KEYWORD_SIZE * 2);
        }
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (cca_is_sha3_mech(&ctx->mech) && !cca_sha3_supported(tokdata)) {
        TRACE_ERROR("SHA-3 mechanism is not supported due to CCA version\n");
        return CKR_MECHANISM_INVALID;
    }

    TRACE_DEBUG("tail_len: %lu, tail: %p, cvl: %lu, sl: %lu\n",
                cca_ctx->tail_len, (void *)cca_ctx->tail,
                cca_ctx->chain_vector_len, cca_ctx->hash_len);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBOWH(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                    rule_array, &cca_ctx->tail_len, cca_ctx->tail,
                    &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                    &cca_ctx->hash_len, cca_ctx->hash);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBOWH (SHA FINAL) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(out_data, cca_ctx->hash, cca_ctx->hash_len);
    *out_data_len = cca_ctx->hash_len;

    /* ctx->context should get freed in digest_mgr_cleanup() */
    return CKR_OK;
}

static long get_mac_len(CK_MECHANISM * mech)
{
    switch (mech->mechanism) {
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC_GENERAL:
        return *(CK_ULONG *) (mech->pParameter);
    case CKM_SHA_1_HMAC:
        return SHA1_HASH_SIZE;
    case CKM_SHA224_HMAC:
        return SHA224_HASH_SIZE;
    case CKM_SHA256_HMAC:
        return SHA256_HASH_SIZE;
    case CKM_SHA384_HMAC:
        return SHA384_HASH_SIZE;
    case CKM_SHA512_HMAC:
        return SHA512_HASH_SIZE;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return -1;
    }
}

static CK_RV ccatok_hmac_init(SIGN_VERIFY_CONTEXT * ctx, CK_MECHANISM * mech,
                              CK_OBJECT_HANDLE key)
{
    struct cca_sha_ctx *cca_ctx;
    long maclen = -1;

    UNUSED(key);

    maclen = get_mac_len(mech);
    if (maclen < 0)
        return CKR_MECHANISM_INVALID;

    ctx->context = calloc(1, sizeof(struct cca_sha_ctx));
    if (ctx->context == NULL) {
        TRACE_ERROR("malloc failed in sha digest init\n");
        return CKR_HOST_MEMORY;
    }
    ctx->context_len = sizeof(struct cca_sha_ctx);

    cca_ctx = (struct cca_sha_ctx *) ctx->context;

    memset(cca_ctx, 0, sizeof(struct cca_sha_ctx));
    cca_ctx->chain_vector_len = CCA_CHAIN_VECTOR_LEN;
    cca_ctx->hash_len = maclen;

    return CKR_OK;
}

CK_RV token_specific_hmac_sign_init(STDLL_TokData_t * tokdata, SESSION * sess,
                                    CK_MECHANISM * mech, CK_OBJECT_HANDLE key)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac_init(&sess->sign_ctx, mech, key);
}

CK_RV token_specific_hmac_verify_init(STDLL_TokData_t * tokdata, SESSION * sess,
                                      CK_MECHANISM * mech, CK_OBJECT_HANDLE key)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac_init(&sess->verify_ctx, mech, key);
}

CK_RV ccatok_hmac(STDLL_TokData_t * tokdata, SIGN_VERIFY_CONTEXT * ctx,
                  CK_BYTE * in_data, CK_ULONG in_data_len, CK_BYTE * signature,
                  CK_ULONG * sig_len, CK_BBOOL sign)
{
    struct cca_sha_ctx *cca_ctx;
    long return_code = 0, reason_code = 0, rule_array_count = 3;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
    OBJECT *key = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc = CKR_OK;

    if (!ctx || !ctx->context) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    cca_ctx = (struct cca_sha_ctx *) ctx->context;

    if (sign && !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        goto done;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA_1_HMAC:
        memcpy(rule_array, "HMAC    SHA-1   ONLY    ", 3 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
        memcpy(rule_array, "HMAC    SHA-224 ONLY    ", 3 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
        memcpy(rule_array, "HMAC    SHA-256 ONLY    ", 3 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
        memcpy(rule_array, "HMAC    SHA-384 ONLY    ", 3 * CCA_KEYWORD_SIZE);
        break;
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
        memcpy(rule_array, "HMAC    SHA-512 ONLY    ", 3 * CCA_KEYWORD_SIZE);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    TRACE_INFO("The mac length is %ld\n", cca_ctx->hash_len);

    if (sign) {
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            dll_CSNBHMG(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        (long int *)&attr->ulValueLen, attr->pValue,
                        (long int *)&in_data_len, in_data,
                        &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                        &cca_ctx->hash_len, cca_ctx->hash);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              attr->pValue, attr->ulValueLen)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBHMG (HMAC GENERATE) failed. "
                        "return:%ld, reason:%ld\n", return_code, reason_code);
            *sig_len = 0;
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        /* Copy the signature into the user supplied variable.
         * For hmac general mechs, only copy over the specified
         * number of bytes for the mac.
         */
        memcpy(signature, cca_ctx->hash, cca_ctx->hash_len);
        *sig_len = cca_ctx->hash_len;
    } else {                    // verify
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            dll_CSNBHMV(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        (long int *)&attr->ulValueLen,
                        attr->pValue, (long int *)&in_data_len, in_data,
                        &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                        &cca_ctx->hash_len, signature);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              attr->pValue, attr->ulValueLen)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code == 4 && (reason_code == 429 || reason_code == 1)) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
            goto done;
        } else if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBHMV (HMAC VERIFY) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        } else if (reason_code != 0) {
            TRACE_WARNING("CSNBHMV (HMAC VERIFY) succeeded, but"
                          " returned reason:%ld\n", reason_code);
        }
    }

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}

CK_RV token_specific_hmac_sign(STDLL_TokData_t * tokdata, SESSION * sess,
                               CK_BYTE * in_data, CK_ULONG in_data_len,
                               CK_BYTE * signature, CK_ULONG * sig_len)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac(tokdata, &sess->sign_ctx, in_data, in_data_len,
                       signature, sig_len, TRUE);
}

CK_RV token_specific_hmac_verify(STDLL_TokData_t * tokdata, SESSION * sess,
                                 CK_BYTE * in_data, CK_ULONG in_data_len,
                                 CK_BYTE * signature, CK_ULONG sig_len)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac(tokdata, &sess->verify_ctx, in_data, in_data_len,
                       signature, &sig_len, FALSE);
}

CK_RV ccatok_hmac_update(STDLL_TokData_t * tokdata, SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE * in_data, CK_ULONG in_data_len, CK_BBOOL sign)
{
    struct cca_sha_ctx *cca_ctx;
    long return_code, reason_code, total, buffer_len;
    long hsize, rule_array_count = 3;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    unsigned char *buffer = NULL;
    CK_ULONG blocksz;
    int use_buffer = 0;
    OBJECT *key = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_MECHANISM_TYPE sha_mech;
    CK_BBOOL generic;
    CK_RV rc = CKR_OK;

    if (!ctx || !ctx->context) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    /* if zero input data, then just do nothing and return.
     * "final" should catch if this is case of hashing zero input.
     */
    if (in_data_len == 0)
        return CKR_OK;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        goto done;
    }

    rc = get_hmac_digest(ctx->mech.mechanism, &sha_mech, &generic);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_hmac_digest failed\n");
        goto done;
    }

    rc = get_sha_block_size(sha_mech, &blocksz);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_sha_block_size failed\n");
        goto done;
    }

    cca_ctx = (struct cca_sha_ctx *) ctx->context;

    /* just send if input a multiple of block size and
     * cca_ctx-> tail is empty.
     */
    if ((cca_ctx->tail_len == 0) && ((in_data_len % blocksz) == 0))
        goto send;

    /* at this point, in_data is not multiple of blocksize
     * and/or there is saved data from previous update still
     * needing to be processed
     */

    /* get totals */
    total = cca_ctx->tail_len + in_data_len;

    /* see if we have enough to fill a block */
    if (total >= (long)blocksz) {
        int remainder;

        remainder = total % blocksz;       // save left over
        buffer_len = total - remainder;

        /* allocate a buffer for sending... */
        if (!(buffer = malloc(buffer_len))) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        /* copy data to send.
         * first get any data saved in tail from prior call,
         * then fill up remaining space in block with in_data
         */
        memcpy(buffer, cca_ctx->tail, cca_ctx->tail_len);
        memcpy(buffer + cca_ctx->tail_len, in_data, in_data_len - remainder);
        use_buffer = 1;

        /* save remainder data for next time */
        if (remainder)
            memcpy(cca_ctx->tail,
                   in_data + (in_data_len - remainder), remainder);
        cca_ctx->tail_len = remainder;
    } else {
        /* not enough to fill a block,
         * so save off data for next round
         */
        memcpy(cca_ctx->tail + cca_ctx->tail_len, in_data, in_data_len);
        cca_ctx->tail_len += in_data_len;
        rc = CKR_OK;
        goto done;
    }

send:
    switch (ctx->mech.mechanism) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
        hsize = SHA1_HASH_SIZE;
        memcpy(rule_array, "HMAC    SHA-1   ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
        hsize = SHA224_HASH_SIZE;
        memcpy(rule_array, "HMAC    SHA-224 ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
        hsize = SHA256_HASH_SIZE;
        memcpy(rule_array, "HMAC    SHA-256 ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
        hsize = SHA384_HASH_SIZE;
        memcpy(rule_array, "HMAC    SHA-384 ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
        hsize = SHA512_HASH_SIZE;
        memcpy(rule_array, "HMAC    SHA-512 ", CCA_KEYWORD_SIZE * 2);
        break;
    }

    if (cca_ctx->part == CCA_HASH_PART_FIRST) {
        memcpy(rule_array + (CCA_KEYWORD_SIZE * 2), "FIRST   ",
               CCA_KEYWORD_SIZE);
        cca_ctx->part = CCA_HASH_PART_MIDDLE;
    } else {
        memcpy(rule_array + (CCA_KEYWORD_SIZE * 2), "MIDDLE  ",
               CCA_KEYWORD_SIZE);
    }

    TRACE_INFO("CSNBHMG: key length is %lu\n", attr->ulValueLen);

    if (sign) {
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            dll_CSNBHMG(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        (long int *)&attr->ulValueLen, attr->pValue,
                        use_buffer ? &buffer_len : (long int *) &in_data_len,
                        use_buffer ? buffer : in_data,
                        &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                        &hsize, cca_ctx->hash);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              attr->pValue, attr->ulValueLen)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBHMG (HMAC SIGN UPDATE) failed. "
                        "return:%ld, reason:%ld\n", return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
        }
    } else {                    // verify
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            dll_CSNBHMV(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        (long int *)&attr->ulValueLen, attr->pValue,
                        use_buffer ? &buffer_len : (long int *) &in_data_len,
                        use_buffer ? buffer : in_data,
                        &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                        &hsize, cca_ctx->hash);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              attr->pValue, attr->ulValueLen)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBHMG (HMAC VERIFY UPDATE) failed. "
                        "return:%ld, reason:%ld\n", return_code, reason_code);
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

CK_RV token_specific_hmac_sign_update(STDLL_TokData_t * tokdata, SESSION * sess,
                                      CK_BYTE * in_data, CK_ULONG in_data_len)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac_update(tokdata, &sess->sign_ctx, in_data,
                              in_data_len, TRUE);
}

CK_RV token_specific_hmac_verify_update(STDLL_TokData_t * tokdata,
                                        SESSION * sess, CK_BYTE * in_data,
                                        CK_ULONG in_data_len)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac_update(tokdata, &sess->verify_ctx, in_data,
                              in_data_len, FALSE);
}

CK_RV ccatok_hmac_final(STDLL_TokData_t * tokdata, SIGN_VERIFY_CONTEXT * ctx,
                        CK_BYTE * signature, CK_ULONG * sig_len, CK_BBOOL sign)
{
    struct cca_sha_ctx *cca_ctx;
    long return_code, reason_code, rule_array_count = 3;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    OBJECT *key = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc = CKR_OK;

    if (!ctx || !ctx->context) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        goto done;
    }

    cca_ctx = (struct cca_sha_ctx *) ctx->context;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
        memcpy(rule_array, "HMAC    SHA-1   ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
        memcpy(rule_array, "HMAC    SHA-224 ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
        memcpy(rule_array, "HMAC    SHA-256 ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
        memcpy(rule_array, "HMAC    SHA-384 ", CCA_KEYWORD_SIZE * 2);
        break;
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
        memcpy(rule_array, "HMAC    SHA-512 ", CCA_KEYWORD_SIZE * 2);
        break;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    if (cca_ctx->part == CCA_HASH_PART_FIRST)
        memcpy(rule_array + (CCA_KEYWORD_SIZE * 2), "ONLY    ",
               CCA_KEYWORD_SIZE);
    else
        memcpy(rule_array + (CCA_KEYWORD_SIZE * 2), "LAST    ",
               CCA_KEYWORD_SIZE);

    TRACE_INFO("CSNBHMG: key length is %lu\n", attr->ulValueLen);
    TRACE_INFO("The mac length is %ld\n", cca_ctx->hash_len);

    if (sign) {
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            dll_CSNBHMG(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        (long int *)&attr->ulValueLen, attr->pValue,
                        &cca_ctx->tail_len, cca_ctx->tail,
                        &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                        &cca_ctx->hash_len, cca_ctx->hash);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              attr->pValue, attr->ulValueLen)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBHMG (HMAC SIGN FINAL) failed. "
                        "return:%ld, reason:%ld\n", return_code, reason_code);
            *sig_len = 0;
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        /* Copy the signature into the user supplied variable.
         * For hmac general mechs, only copy over the specified
         * number of bytes for the mac.
         */
        memcpy(signature, cca_ctx->hash, cca_ctx->hash_len);
        *sig_len = cca_ctx->hash_len;

    } else {                    // verify
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            dll_CSNBHMV(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        (long int *)&attr->ulValueLen, attr->pValue,
                        &cca_ctx->tail_len, cca_ctx->tail,
                        &cca_ctx->chain_vector_len, cca_ctx->chain_vector,
                        &cca_ctx->hash_len, signature);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              attr->pValue, attr->ulValueLen)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code == 4 && (reason_code == 429 || reason_code == 1)) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
            goto done;
        } else if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBHMV (HMAC VERIFY) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        } else if (reason_code != 0) {
            TRACE_WARNING("CSNBHMV (HMAC VERIFY) succeeded, but"
                          " returned reason:%ld\n", reason_code);
        }

    }

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}

CK_RV token_specific_hmac_sign_final(STDLL_TokData_t * tokdata, SESSION * sess,
                                     CK_BYTE * signature, CK_ULONG * sig_len)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac_final(tokdata, &sess->sign_ctx, signature, sig_len,
                             TRUE);
}

CK_RV token_specific_hmac_verify_final(STDLL_TokData_t * tokdata,
                                       SESSION * sess, CK_BYTE * signature,
                                       CK_ULONG sig_len)
{
    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    return ccatok_hmac_final(tokdata, &sess->verify_ctx, signature,
                             &sig_len, FALSE);
}

CK_RV token_create_ibm_dilithium_keypair(TEMPLATE *publ_tmpl,
                                         TEMPLATE *priv_tmpl,
                                         const struct pqc_oid *oid,
                                         CK_ULONG priv_tok_len,
                                         CK_BYTE *priv_tok,
                                         CK_ULONG publ_tok_len,
                                         CK_BYTE *publ_tok)
{
    CK_RV rc;
    uint16_t publsec_len, rho_len, t1_len;
    CK_BYTE *spki = NULL;
    CK_ULONG spki_len = 0;

    publsec_len = be16toh(*((uint16_t *)
                            (publ_tok + CCA_QSA_EXTTOK_PUBLKEY_OFFSET + 2)));
    if (CCA_QSA_EXTTOK_PUBLKEY_OFFSET + publsec_len > (int)publ_tok_len) {
        TRACE_ERROR("CCA QSA key token has invalid publ section len or "
                    "token size\n");
        return CKR_FUNCTION_FAILED;
    }

    rho_len = be16toh(*((uint16_t *)(publ_tok + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                     CCA_QSA_EXTTOK_RHO_OFFSET)));
    t1_len = be16toh(*((uint16_t *)(publ_tok + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                    CCA_QSA_EXTTOK_T1_OFFSET)));

    if (rho_len != oid->len_info.dilithium.rho_len ||
        t1_len != oid->len_info.dilithium.t1_len) {
        TRACE_ERROR("CCA QSA key token has invalid key component length\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Add attributes RHO and T1 to private and public template */
    rc = ibm_dilithium_unpack_pub_key(publ_tok + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                      CCA_QSA_EXTTOK_PAYLOAD_OFFSET,
                                      publ_tok_len -
                                      CCA_QSA_EXTTOK_PUBLKEY_OFFSET -
                                      CCA_QSA_EXTTOK_PAYLOAD_OFFSET,
                                      oid, publ_tmpl);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_unpack_pub_key failed\n");
        return rc;
    }

    rc = ibm_dilithium_unpack_pub_key(publ_tok + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                      CCA_QSA_EXTTOK_PAYLOAD_OFFSET,
                                      publ_tok_len -
                                      CCA_QSA_EXTTOK_PUBLKEY_OFFSET -
                                      CCA_QSA_EXTTOK_PAYLOAD_OFFSET,
                                      oid, priv_tmpl);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_unpack_pub_key failed\n");
        return rc;
    }

    /* Add keyform and mode attributes to public and private template */
    rc = ibm_pqc_add_keyform_mode(publ_tmpl, oid, CKM_IBM_DILITHIUM);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        return rc;
    }

    rc = ibm_pqc_add_keyform_mode(priv_tmpl, oid, CKM_IBM_DILITHIUM);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        return rc;
    }

    /* Add SPKI as CKA_VALUE to public template */
    rc = ibm_dilithium_publ_get_spki(publ_tmpl, FALSE, &spki, &spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_publ_get_spki failed\n");
        return rc;
    }

    rc = build_update_attribute(publ_tmpl, CKA_VALUE, spki, spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_update_attribute for CKA_VALUE failed rv=0x%lx\n",
                    rc);
        free(spki);
        return rc;
    }

    free(spki);

    /* store publ key token into CKA_IBM_OPAQUE of the public key object */
    rc = build_update_attribute(publ_tmpl, CKA_IBM_OPAQUE,
                                publ_tok, publ_tok_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_update_attribute for publ_tok failed rv=0x%lx\n",
                    rc);
        return rc;
    }

    /* store priv key token into CKA_IBM_OPAQUE of the private key object */
    rc = build_update_attribute(priv_tmpl, CKA_IBM_OPAQUE,
                                priv_tok, priv_tok_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_update_attribute for priv_tok failed rv=0x%lx\n",
                    rc);
        return rc;
    }

    return CKR_OK;
}

static CK_RV build_ibm_dilithium_key_value_struct(const struct pqc_oid *oid,
                                            unsigned char *key_value_structure,
                                            long *key_value_structure_length)
{
    uint8_t algo_id, format = CCA_QSA_CLEAR_FORMAT_NO_KEY;
    uint16_t algo_param, clear_len = 0;

    if (*key_value_structure_length < CCA_QSA_KEY_VALUE_STRUCT_SIZE)
        return CKR_ARGUMENTS_BAD;

    switch (oid->keyform) {
    case CK_IBM_DILITHIUM_KEYFORM_ROUND2_65:
        algo_id = CCA_QSA_ALGO_DILITHIUM_ROUND_2;
        algo_param = htobe16(CCA_QSA_ALGO_DILITHIUM_65);
        break;
    case CK_IBM_DILITHIUM_KEYFORM_ROUND2_87:
        algo_id = CCA_QSA_ALGO_DILITHIUM_ROUND_2;
        algo_param = htobe16(CCA_QSA_ALGO_DILITHIUM_87);
        break;
    case CK_IBM_DILITHIUM_KEYFORM_ROUND3_65:
        algo_id = CCA_QSA_ALGO_DILITHIUM_ROUND_3;
        algo_param = htobe16(CCA_QSA_ALGO_DILITHIUM_65);
        break;
    case CK_IBM_DILITHIUM_KEYFORM_ROUND3_87:
        algo_id = CCA_QSA_ALGO_DILITHIUM_ROUND_3;
        algo_param = htobe16(CCA_QSA_ALGO_DILITHIUM_87);
        break;
    default:
        TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                    oid->keyform);
        return CKR_KEY_SIZE_RANGE;
    }

    /*
     * See CCA doc for offset of data in key_value_structure
     */
    memcpy(key_value_structure, &algo_id, sizeof(uint8_t));
    memcpy(&key_value_structure[CCA_PKB_QSA_CLEAR_FORMAT_OFFSET], &format,
           sizeof(uint8_t));
    memcpy(&key_value_structure[CCA_PKB_QSA_ALGO_PARAM_OFFSET],
           &algo_param, sizeof(uint16_t));
    memcpy(&key_value_structure[CCA_PKB_QSA_CLEAR_LEN_OFFSET],
           &clear_len, sizeof(uint16_t));

    *key_value_structure_length = CCA_QSA_KEY_VALUE_STRUCT_SIZE;

    return CKR_OK;
}

CK_RV token_specific_ibm_dilithium_generate_keypair(STDLL_TokData_t *tokdata,
                                                    const struct pqc_oid *oid,
                                                    TEMPLATE *publ_tmpl,
                                                    TEMPLATE *priv_tmpl)
{
    long return_code, reason_code, rule_array_count, exit_data_len = 0;
    unsigned char *exit_data = NULL;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long key_value_structure_length, private_key_name_length, key_token_length;
    unsigned char key_value_structure[CCA_QSA_KEY_VALUE_STRUCT_SIZE] = { 0, };
    unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
    unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    long regeneration_data_length;
    long priv_key_token_length, publ_key_token_length;
    unsigned char regeneration_data[CCA_REGENERATION_DATA_SIZE] = { 0, };
    unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
    unsigned char priv_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    unsigned char publ_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    CK_RV rv;
    long param1 = 0;
    unsigned char *param2 = NULL;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!cca_pqc_strength_supported(tokdata, CKM_IBM_DILITHIUM, oid->keyform)) {
        TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                    oid->keyform);
        return CKR_KEY_SIZE_RANGE;
    }

    key_value_structure_length = CCA_QSA_KEY_VALUE_STRUCT_SIZE;
    rv = build_ibm_dilithium_key_value_struct(oid, key_value_structure,
                                              &key_value_structure_length);
    if (rv != CKR_OK) {
        TRACE_ERROR("build_ibm_dilithium_key_value_struct failed: 0x%lx\n", rv);
        return rv;
    }

    rule_array_count = 2;
    memcpy(rule_array, "QSA-PAIRU-DIGSIG", (size_t) (CCA_KEYWORD_SIZE * 2));

    private_key_name_length = 0;

    key_token_length = CCA_KEY_TOKEN_SIZE;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKB(&return_code,
                    &reason_code,
                    &exit_data_len,
                    exit_data,
                    &rule_array_count,
                    rule_array,
                    &key_value_structure_length,
                    key_value_structure,
                    &private_key_name_length,
                    private_key_name,
                    &param1,
                    param2,
                    &param1,
                    param2,
                    &param1,
                    param2,
                    &param1, param2,
                    &param1, param2, &key_token_length, key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKB (QSA KEY TOKEN BUILD) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    rule_array_count = 1;
    memset(rule_array, 0, sizeof(rule_array));
    memcpy(rule_array, "MASTER  ", (size_t) CCA_KEYWORD_SIZE);

    priv_key_token_length = CCA_KEY_TOKEN_SIZE;

    regeneration_data_length = 0;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKG(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    &regeneration_data_length,
                    regeneration_data,
                    &key_token_length,
                    key_token,
                    transport_key_identifier,
                    &priv_key_token_length, priv_key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKG (QSA KEY GENERATE) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(priv_key_token, priv_key_token_length,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been generated\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rv = cca_reencipher_created_key(tokdata, priv_tmpl, priv_key_token,
                                    priv_key_token_length, new_mk, keytype,
                                    FALSE);
    if (rv != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rv);
        return rv;
    }

    TRACE_DEVEL("Dilithium secure private key token generated. size: %ld\n",
                priv_key_token_length);

    rule_array_count = 0;
    publ_key_token_length = CCA_KEY_TOKEN_SIZE;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKX(&return_code, &reason_code,
                    NULL, NULL,
                    &rule_array_count, rule_array,
                    &priv_key_token_length, priv_key_token,
                    &publ_key_token_length, publ_key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKX (PUBLIC KEY TOKEN EXTRACT) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    TRACE_DEVEL("Dilithium secure public key token generated. size: %ld\n",
                publ_key_token_length);

    rv = token_create_ibm_dilithium_keypair(publ_tmpl, priv_tmpl, oid,
                                            priv_key_token_length,
                                            priv_key_token,
                                            publ_key_token_length,
                                            publ_key_token);
    if (rv != CKR_OK) {
        TRACE_DEVEL("token_create_ibm_dilithium_keypair failed. rv: %lu\n", rv);
        return rv;
    }

    TRACE_DEBUG("%s: priv template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(priv_tmpl);
    TRACE_DEBUG("%s: publ template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(publ_tmpl);

    return rv;
}

static CK_RV check_ibm_dilithium_data_len(const struct pqc_oid *oid,
                                          CK_ULONG in_data_len)
{
    switch (oid->keyform) {
    case CK_IBM_DILITHIUM_KEYFORM_ROUND2_65:
    case CK_IBM_DILITHIUM_KEYFORM_ROUND3_65:
        if (in_data_len > CCA_MAX_DILITHIUM_65_DATA_LEN) {
            TRACE_DEVEL("Input too large for Dilithium keyform %lu\n",
                        oid->keyform);
            return CKR_DATA_LEN_RANGE;
        }
        break;
    case CK_IBM_DILITHIUM_KEYFORM_ROUND2_87:
    case CK_IBM_DILITHIUM_KEYFORM_ROUND3_87:
        if (in_data_len > CCA_MAX_DILITHIUM_87_DATA_LEN) {
            TRACE_DEVEL("Input too large for Dilithium keyform %lu\n",
                        oid->keyform);
            return CKR_DATA_LEN_RANGE;
        }
        break;
    default:
        TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                    oid->keyform);
        return CKR_KEY_SIZE_RANGE;
    }

    return CKR_OK;
}

CK_RV token_specific_ibm_dilithium_sign(STDLL_TokData_t *tokdata,
                                        SESSION *sess,
                                        CK_BBOOL length_only,
                                        const struct pqc_oid *oid,
                                        CK_BYTE *in_data,
                                        CK_ULONG in_data_len,
                                        CK_BYTE *signature,
                                        CK_ULONG *signature_len,
                                        OBJECT *key_obj)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long signature_bit_length;
    CK_ATTRIBUTE *attr;
    CK_RV rc;

    UNUSED(sess);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!cca_pqc_strength_supported(tokdata, CKM_IBM_DILITHIUM, oid->keyform)) {
        TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                    oid->keyform);
        return CKR_KEY_SIZE_RANGE;
    }

    rc = check_ibm_dilithium_data_len(oid, in_data_len);
    if (rc != CKR_OK)
        return rc;

    if (length_only) {
        *signature_len = CCA_MAX_DILITHIUM_SIGNATURE_LEN;
        return CKR_OK;
    }

    if (*signature_len > CCA_MAX_DILITHIUM_SIGNATURE_LEN)
        *signature_len = CCA_MAX_DILITHIUM_SIGNATURE_LEN;

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    rule_array_count = 3;
    memcpy(rule_array, "CRDL-DSAMESSAGE CRDLHASH", CCA_KEYWORD_SIZE * 3);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSG(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *)&(attr->ulValueLen),
                    attr->pValue,
                    (long *)&in_data_len,
                    in_data,
                    (long *)signature_len, &signature_bit_length, signature);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSG (QSA SIGN) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDDSG (QSA SIGN) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }

    return CKR_OK;
}

CK_RV token_specific_ibm_dilithium_verify(STDLL_TokData_t *tokdata,
                                          SESSION *sess,
                                          const struct pqc_oid *oid,
                                          CK_BYTE *in_data,
                                          CK_ULONG in_data_len,
                                          CK_BYTE *signature,
                                          CK_ULONG signature_len,
                                          OBJECT *key_obj)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    CK_ATTRIBUTE *attr;
    CK_RV rc;

    UNUSED(sess);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!cca_pqc_strength_supported(tokdata, CKM_IBM_DILITHIUM, oid->keyform)) {
        TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                    oid->keyform);
        return CKR_KEY_SIZE_RANGE;
    }

    rc = check_ibm_dilithium_data_len(oid, in_data_len);
    if (rc != CKR_OK)
        return rc;

    /* Find the secure key token */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    rule_array_count = 3;
    memcpy(rule_array, "CRDL-DSAMESSAGE CRDLHASH", CCA_KEYWORD_SIZE * 3);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDDSV(&return_code,
                    &reason_code,
                    NULL,
                    NULL,
                    &rule_array_count,
                    rule_array,
                    (long *)&(attr->ulValueLen),
                    attr->pValue,
                    (long *)&in_data_len,
                    in_data, (long *)&signature_len, signature);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, attr->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code == 4 && reason_code == 429) {
        return CKR_SIGNATURE_INVALID;
    } else if (return_code == 12 && reason_code == 769) {
        return CKR_SIGNATURE_INVALID;
    } else if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDDSV (QSA VERIFY) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    } else if (reason_code != 0) {
        TRACE_WARNING("CSNDDSV (QSA VERIFY) succeeded, but"
                      " returned reason:%ld\n", reason_code);
    }

    return CKR_OK;
}

static CK_RV import_rsa_privkey(STDLL_TokData_t *tokdata, TEMPLATE * priv_tmpl)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;
    enum cca_token_type token_type;
    unsigned int token_keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;

    rc = template_attribute_find(priv_tmpl, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure rsa private key which
         * is stored in the CKA_IBM_OPAQUE attribute.
         */
        CK_BYTE *t, n[CCATOK_MAX_N_LEN], e[CCATOK_MAX_E_LEN];
        CK_ULONG n_len = CCATOK_MAX_N_LEN, e_len = CCATOK_MAX_E_LEN;
        uint16_t privkey_len, pubkey_offset;

        CK_BBOOL true = TRUE;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_keybitsize, &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (token_type != sec_rsa_priv_key) {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_RSA\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, priv_tmpl,
                                        opaque_attr->pValue,
                                        opaque_attr->ulValueLen,
                                        new_mk, token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        t = opaque_attr->pValue;
        privkey_len = cca_rsa_inttok_privkey_get_len(&t[CCA_RSA_INTTOK_PRIVKEY_OFFSET]);
        pubkey_offset = CCA_RSA_INTTOK_HDR_LENGTH + privkey_len;

        /* modulus n is stored in the private (!) key area, get it there */
        rc =  cca_rsa_inttok_privkeysec_get_n(&t[CCA_RSA_INTTOK_PRIVKEY_OFFSET], &n_len, n);
        if (rc != CKR_OK) {
            TRACE_DEVEL("cca_inttok_privkey_get_n() failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* Add/update CKA_SENSITIVE */
        rc = build_update_attribute(priv_tmpl, CKA_SENSITIVE, &true, sizeof(CK_BBOOL));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for CKA_SENSITIVE failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* get public exponent e */
        rc = cca_rsa_inttok_pubkeysec_get_e(&t[pubkey_offset], &e_len, e);
        if (rc != CKR_OK) {
            TRACE_DEVEL("cca_inttok_pubkey_get_e() failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* add n's value to the template */
        rc = build_update_attribute(priv_tmpl, CKA_MODULUS, n, n_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for n failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* Add e's value to the template */
        rc = build_update_attribute(priv_tmpl, CKA_PUBLIC_EXPONENT, e, e_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for e failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* Add dummy attributes to satisfy PKCS#11 */
        rc = build_update_attribute(priv_tmpl, CKA_PRIVATE_EXPONENT, NULL, 0);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for d failed. rc=0x%lx\n", rc);
            return rc;
        }

    } else {
        /*
         * This is an import of a clear key value which is to be transfered
         * into a CCA RSA private key.
         */

        long return_code, reason_code, rule_array_count, total = 0;
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

        long offset, key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
        long private_key_name_length, key_token_length, target_key_token_length;

        unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
        unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
        unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        unsigned char target_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };

        uint16_t size_of_e, size_of_d;
        uint16_t mod_bits, mod_bytes, bytes;
        CK_ATTRIBUTE *pub_exp = NULL, *mod = NULL,
            *p_prime = NULL, *q_prime = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp =
            NULL, *priv_exp = NULL;
        CK_BBOOL is_me_format = FALSE;

        /* Try to get CRT key components (no rc checking) */
        template_attribute_get_non_empty(priv_tmpl, CKA_PRIME_1, &p_prime);
        template_attribute_get_non_empty(priv_tmpl, CKA_PRIME_2, &q_prime);
        template_attribute_get_non_empty(priv_tmpl, CKA_EXPONENT_1, &dmp1);
        template_attribute_get_non_empty(priv_tmpl, CKA_EXPONENT_2, &dmq1);
        template_attribute_get_non_empty(priv_tmpl, CKA_COEFFICIENT, &iqmp);

        if (p_prime == NULL || q_prime == NULL || dmp1 == NULL ||
            dmq1 == NULL || iqmp == NULL) {
            /* No CRT components, then get private exponent instead */
            rc = template_attribute_get_non_empty(priv_tmpl,
                                                  CKA_PRIVATE_EXPONENT,
                                                  &priv_exp);
            if (rc != CKR_OK) {
                TRACE_ERROR("CKA_PRIVATE_EXPONENT attribute missing for ME.\n");
                return rc;
            }

            is_me_format = TRUE;
        }

        /* Public exponent and Modulus are always required */
        rc = template_attribute_get_non_empty(priv_tmpl, CKA_PUBLIC_EXPONENT,
                                              &pub_exp);
        if (rc != CKR_OK) {
            TRACE_ERROR("CKA_PUBLIC_EXPONENT attribute missing for CRT/ME.\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(priv_tmpl, CKA_MODULUS, &mod);
        if (rc != CKR_OK) {
            TRACE_ERROR("CKA_MODULUS attribute missing for CRT/ME.\n");
            return rc;
        }

        if (is_me_format) {
            total += priv_exp->ulValueLen;
            total += pub_exp->ulValueLen;
            total += mod->ulValueLen;

            /* check total length does not exceed key_value_structure_length */
            if ((total + 8) > key_value_structure_length) {
                TRACE_ERROR("total length of key exceeds "
                            "CCA_KEY_VALUE_STRUCT_SIZE.\n");
                return CKR_KEY_SIZE_RANGE;
            }

            /* Build key token for RSA-AESM format.
             * Fields according to Table 9.
             * PKA_Key_Token_Build key-values-structure
             */
            memset(key_value_structure, 0, key_value_structure_length);

            /* Field #1 - Length of modulus in bits */
            mod_bits = htobe16(mod->ulValueLen * 8);
            memcpy(&key_value_structure[0], &mod_bits, sizeof(uint16_t));

            /* Field #2 - Length of modulus field in bytes */
            mod_bytes = htobe16(mod->ulValueLen);
            memcpy(&key_value_structure[2], &mod_bytes, sizeof(uint16_t));

            /* Field #3 - Length of public exponent field in bytes */
            size_of_e = htobe16(pub_exp->ulValueLen);
            memcpy(&key_value_structure[4], &size_of_e, sizeof(uint16_t));

            /* Field #4 - Length of private exponent field in bytes */
            size_of_d = htobe16(priv_exp->ulValueLen);
            memcpy(&key_value_structure[6], &size_of_d, sizeof(uint16_t));

            /* Field #5 - Modulus */
            memcpy(&key_value_structure[8], mod->pValue, mod->ulValueLen);

            offset = 8 + mod->ulValueLen;

            /* Field #6 - Public Exponent */
            memcpy(&key_value_structure[offset], pub_exp->pValue,
                   pub_exp->ulValueLen);

            offset += pub_exp->ulValueLen;

            /* Field #7 - Private Exponent */
            memcpy(&key_value_structure[offset], priv_exp->pValue,
                   priv_exp->ulValueLen);

            rule_array_count = 2;
            memcpy(rule_array, "RSA-AESMKEY-MGMT", (CCA_KEYWORD_SIZE * 2));
        } else  {
            /* CRT format */
            total += p_prime->ulValueLen;
            total += q_prime->ulValueLen;
            total += dmp1->ulValueLen;
            total += dmq1->ulValueLen;
            total += iqmp->ulValueLen;
            total += pub_exp->ulValueLen;
            total += mod->ulValueLen;

            /* check total length does not exceed key_value_structure_length */
            if ((total + 18) > key_value_structure_length) {
                TRACE_ERROR("total length of key exceeds "
                            "CCA_KEY_VALUE_STRUCT_SIZE.\n");
                return CKR_KEY_SIZE_RANGE;
            }

            /* Build key token for RSA-AESC format.
             * Fields according to Table 9.
             * PKA_Key_Token_Build key-values-structure
             */
            memset(key_value_structure, 0, key_value_structure_length);

            /* Field #1 - Length of modulus in bits */
            mod_bits = htobe16(mod->ulValueLen * 8);
            memcpy(&key_value_structure[0], &mod_bits, sizeof(uint16_t));

            /* Field #2 - Length of modulus field in bytes */
            mod_bytes = htobe16(mod->ulValueLen);
            memcpy(&key_value_structure[2], &mod_bytes, sizeof(uint16_t));

            /* Field #3 - Length of public exponent field in bytes */
            size_of_e = htobe16(pub_exp->ulValueLen);
            memcpy(&key_value_structure[4], &size_of_e, sizeof(uint16_t));

            /* Field #4 - Reserved, binary zero, two bytes */

            /* Field #5 - Length of prime P */
            bytes = htobe16(p_prime->ulValueLen);
            memcpy(&key_value_structure[8], &bytes, sizeof(uint16_t));

            /* Field #6 - Length of prime Q */
            bytes = htobe16(q_prime->ulValueLen);
            memcpy(&key_value_structure[10], &bytes, sizeof(uint16_t));

            /* Field #7 - Length of dp in bytes */
            bytes = htobe16(dmp1->ulValueLen);
            memcpy(&key_value_structure[12], &bytes, sizeof(uint16_t));

            /* Field #8 - Length of dq in bytes */
            bytes = htobe16(dmq1->ulValueLen);
            memcpy(&key_value_structure[14], &bytes, sizeof(uint16_t));

            /* Field #9 - Length of U in bytes */
            bytes = htobe16(iqmp->ulValueLen);
            memcpy(&key_value_structure[16], &bytes, sizeof(uint16_t));

            /* Field #10 - Modulus */
            memcpy(&key_value_structure[18], mod->pValue, mod->ulValueLen);

            offset = 18 + mod->ulValueLen;

            /* Field #11 - Public Exponent */
            memcpy(&key_value_structure[offset], pub_exp->pValue,
                   pub_exp->ulValueLen);

            offset += pub_exp->ulValueLen;

            /* Field #12 - Prime numer, p */
            memcpy(&key_value_structure[offset], p_prime->pValue,
                   p_prime->ulValueLen);

            offset += p_prime->ulValueLen;

            /* Field #13 - Prime numer, q */
            memcpy(&key_value_structure[offset], q_prime->pValue,
                   q_prime->ulValueLen);

            offset += q_prime->ulValueLen;

            /* Field #14 - dp = dmod(p-1) */
            memcpy(&key_value_structure[offset], dmp1->pValue,
                   dmp1->ulValueLen);

            offset += dmp1->ulValueLen;

            /* Field #15 - dq = dmod(q-1) */
            memcpy(&key_value_structure[offset], dmq1->pValue,
                   dmq1->ulValueLen);

            offset += dmq1->ulValueLen;

            /* Field #16 - U = (q^-1)mod(p)  */
            memcpy(&key_value_structure[offset], iqmp->pValue,
                   iqmp->ulValueLen);

            rule_array_count = 2;
            memcpy(rule_array, "RSA-AESCKEY-MGMT", (CCA_KEYWORD_SIZE * 2));
        }

        /* Now build a key token with the imported public key */
        private_key_name_length = 0;

        key_token_length = CCA_KEY_TOKEN_SIZE;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKB(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        &key_value_structure_length, key_value_structure,
                        &private_key_name_length, private_key_name,
                        0, NULL, 0, NULL,
                        0, NULL, 0, NULL, 0, NULL,
                        &key_token_length, key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKB (RSA KEY TOKEN BUILD RSA CRT) failed."
                        " return:%ld, reason:%ld\n", return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
            goto err;
        }

        /* Now import the PKA key token */
        rule_array_count = 0;

        target_key_token_length = CCA_KEY_TOKEN_SIZE;

        key_token_length = CCA_KEY_TOKEN_SIZE;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKI(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        &key_token_length, key_token,
                        transport_key_identifier, &target_key_token_length,
                        target_key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKI (RSA KEY TOKEN IMPORT) failed."
                        " return:%ld, reason:%ld\n", return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
            goto err;
        }

        if (analyse_cca_key_token(target_key_token, target_key_token_length,
                                  &token_type, &token_keybitsize, &mkvp) == FALSE ||
            mkvp == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, priv_tmpl, target_key_token,
                                        target_key_token_length, new_mk,
                                        token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }


        /* Add the key object to the template */
        if ((rc = build_update_attribute(priv_tmpl, CKA_IBM_OPAQUE,
                                         target_key_token,
                                         target_key_token_length))) {
            TRACE_DEVEL("build_update_attribute failed\n");
            goto err;
        }

        if (p_prime != NULL)
            OPENSSL_cleanse(p_prime->pValue, p_prime->ulValueLen);
        if (q_prime != NULL)
            OPENSSL_cleanse(q_prime->pValue, q_prime->ulValueLen);
        if (dmp1 != NULL)
            OPENSSL_cleanse(dmp1->pValue, dmp1->ulValueLen);
        if (dmq1 != NULL)
            OPENSSL_cleanse(dmq1->pValue, dmq1->ulValueLen);
        if (iqmp != NULL)
            OPENSSL_cleanse(iqmp->pValue, iqmp->ulValueLen);
        if (priv_exp != NULL)
            OPENSSL_cleanse(priv_exp->pValue, priv_exp->ulValueLen);

        rc = CKR_OK;

err:
        OPENSSL_cleanse(key_value_structure, sizeof(key_value_structure));
    }

    if (rc == CKR_OK) {
        TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
        TRACE_DEBUG_DUMPTEMPL(priv_tmpl);
    }

    return rc;
}

static CK_RV import_rsa_pubkey(STDLL_TokData_t *tokdata, TEMPLATE *publ_tmpl)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;

    rc = template_attribute_find(publ_tmpl, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure rsa public key which
         * is stored in the CKA_IBM_OPAQUE attribute.
         */

        enum cca_token_type token_type;
        unsigned int token_keybitsize;
        CK_BYTE *t, n[CCATOK_MAX_N_LEN], e[CCATOK_MAX_E_LEN];
        CK_ULONG n_len = CCATOK_MAX_N_LEN, e_len = CCATOK_MAX_E_LEN;
        const CK_BYTE *mkvp;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_keybitsize, &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (token_type != sec_rsa_publ_key) {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_RSA\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        t = opaque_attr->pValue;

        /* extract modulus n from public key section */
        rc = cca_rsa_exttok_pubkeysec_get_n(&t[CCA_RSA_EXTTOK_PUBKEY_OFFSET], &n_len, n);
        if (rc != CKR_OK) {
            TRACE_DEVEL("cca_exttok_pubkey_get_n() failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* extract exponent e from public key section */
        rc = cca_rsa_exttok_pubkeysec_get_e(&t[CCA_RSA_EXTTOK_PUBKEY_OFFSET], &e_len, e);
        if (rc != CKR_OK) {
            TRACE_DEVEL("cca_exttok_pubkey_get_e() failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* add n's value to the template */
        rc = build_update_attribute(publ_tmpl, CKA_MODULUS, n, n_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for n failed. rc=0x%lx\n", rc);
            return rc;
        }

        /* Add e's value to the template */
        rc = build_update_attribute(publ_tmpl, CKA_PUBLIC_EXPONENT, e, e_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for e failed. rc=0x%lx\n", rc);
            return rc;
        }

    } else {
        /*
         * This is an import of a clear key value which is to be transfered
         * into a CCA RSA public key.
         */

        long return_code, reason_code, rule_array_count;
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

        long key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
        long private_key_name_length, key_token_length;
        unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
        unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
        unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

        uint16_t size_of_e;
        uint16_t mod_bits, mod_bytes;
        CK_ATTRIBUTE *pub_exp = NULL;
        CK_ATTRIBUTE *pub_mod = NULL, *attr = NULL;

        /* check that modulus and public exponent are available */
        rc = template_attribute_get_non_empty(publ_tmpl, CKA_PUBLIC_EXPONENT,
                                              &pub_exp);
        if (rc != CKR_OK) {
            TRACE_ERROR("CKA_PUBLIC_EXPONENT attribute missing.\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(publ_tmpl, CKA_MODULUS, &pub_mod);
        if (rc != CKR_OK) {
            TRACE_ERROR("CKA_MODULUS attribute missing.\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(publ_tmpl, CKA_MODULUS_BITS, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("CKA_MODULUS_BITS attribute missing.\n");
            return rc;
        }

        /* check total length does not exceed key_value_structure_length */
        if ((pub_mod->ulValueLen + 8 + pub_exp->ulValueLen) >
                                    (CK_ULONG)key_value_structure_length) {
            TRACE_ERROR("total length of key exceeds CCA_KEY_VALUE_STRUCT_SIZE.\n");
            return CKR_KEY_SIZE_RANGE;
        }

        /* In case the application hasn't filled it */
        if (*(CK_ULONG *) attr->pValue == 0)
            mod_bits = htobe16(pub_mod->ulValueLen * 8);
        else
            mod_bits = htobe16(*(CK_ULONG *) attr->pValue);

        /* Build key token for RSA-PUBL format */
        memset(key_value_structure, 0, key_value_structure_length);

        /* Fields according to Table 9.
         * PKA_Key_Token_Build key-values-structure
         */

        /* Field #1 - Length of modulus in bits */
        memcpy(&key_value_structure[0], &mod_bits, sizeof(uint16_t));

        /* Field #2 - Length of modulus field in bytes */
        mod_bytes = htobe16(pub_mod->ulValueLen);
        memcpy(&key_value_structure[2], &mod_bytes, sizeof(uint16_t));

        /* Field #3 - Length of public exponent field in bytes */
        size_of_e = htobe16((uint16_t) pub_exp->ulValueLen);
        memcpy(&key_value_structure[4], &size_of_e, sizeof(uint16_t));

        /* Field #4 - private key exponent length; skip */

        /* Field #5 - Modulus */
        memcpy(&key_value_structure[8], pub_mod->pValue,
               (size_t) pub_mod->ulValueLen);

        /* Field #6 - Public exponent. Its offset depends on modulus size */
        memcpy(&key_value_structure[8 + pub_mod->ulValueLen],
               pub_exp->pValue, (size_t) pub_exp->ulValueLen);

        /* Field #7 - Private exponent. Skip */

        rule_array_count = 1;
        memcpy(rule_array, "RSA-PUBL", (size_t) (CCA_KEYWORD_SIZE * 1));

        private_key_name_length = 0;

        key_token_length = CCA_KEY_TOKEN_SIZE;

        // Create a key token for the public key.
        // Public keys do not need to be wrapped, so just call PKB.
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKB(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        &key_value_structure_length, key_value_structure,
                        &private_key_name_length, private_key_name,
                        0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL,
                        &key_token_length, key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKB (RSA KEY TOKEN BUILD RSA-PUBL) failed."
                        " return:%ld, reason:%ld\n", return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }
        // Add the key object to the template.
        if ((rc = build_update_attribute(publ_tmpl, CKA_IBM_OPAQUE,
                                         key_token, key_token_length))) {
            TRACE_DEVEL("build_update_attribute failed\n");
            return rc;
        }
    }

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(publ_tmpl);

    return CKR_OK;
}

static CK_RV import_symmetric_key(STDLL_TokData_t *tokdata,
                                  OBJECT * object, CK_ULONG keytype)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;
    enum cca_token_type token_type;
    unsigned int token_keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk, exp, cpacf_exp;

    rc = template_attribute_find(object->template, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure key which is stored in
         * the CKA_IBM_OPAQUE attribute. The CKA_VALUE attribute is only
         * a dummy reflecting the clear key byte size. However, let's
         * check if the template attributes match to the cca key in the
         * CKA_IBM_OPAQUE attribute.
         */
        CK_BYTE zorro[32] = { 0 };
        CK_BBOOL true = TRUE;
        CK_ULONG value_len = 0;
        CK_IBM_CCA_AES_KEY_MODE_TYPE mode;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_keybitsize, &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (keytype == CKK_DES) {
            if (token_type != sec_des_data_key) {
                TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_DES\n");
                return CKR_TEMPLATE_INCONSISTENT;
            }
            if (token_keybitsize != 8 * 8) {
                TRACE_ERROR("CCA token keybitsize %u does not match to keytype CKK_DES\n",
                            token_keybitsize);
                return CKR_TEMPLATE_INCONSISTENT;
            }
        } else if (keytype == CKK_DES3) {
            if (token_type != sec_des_data_key) {
                TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_DES3\n");
                return CKR_TEMPLATE_INCONSISTENT;
            }
            if (token_keybitsize != 8 * 24) {
                TRACE_ERROR("CCA token keybitsize %u does not match to keytype CKK_DES3\n",
                            token_keybitsize);
                return CKR_TEMPLATE_INCONSISTENT;
            }
        } else if (keytype == CKK_AES) {
            if (token_type == sec_aes_data_key) {
                /* keybitsize has been checked by the analyse_cca_key_token() function */
                mode = CK_IBM_CCA_AES_DATA_KEY;
            } else if (token_type == sec_aes_cipher_key) {
                mode = CK_IBM_CCA_AES_CIPHER_KEY;
                if (token_keybitsize == 0) {
                    /*
                     * A CIPHER key with V1 payload does not allow to obtain the
                     * keybitsize. The user must supply the CKA_VALUE_LEN with
                     * a valid key size in the template.
                     */
                    rc = template_attribute_get_ulong(object->template,
                                                      CKA_VALUE_LEN,
                                                      &value_len);
                    if (rc != CKR_OK || value_len == 0) {
                        TRACE_ERROR("For an AES CIPHER key token with V1 "
                                    "payload attribute CKA_VALUE_LEN must also "
                                    "be supplied to specify the key size\n");
                        return CKR_TEMPLATE_INCONSISTENT;
                    }
                    if (value_len != 16 && value_len != 24 && value_len != 32) {
                        TRACE_ERROR("CKA_VALUE_LEN not valid for an AES key\n");
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    token_keybitsize = value_len * 8;
                }

                rc = ccatok_var_sym_token_is_exportable(opaque_attr->pValue,
                                                        opaque_attr->ulValueLen,
                                                        &exp, &cpacf_exp);
                if (rc != CKR_OK)
                    return rc;

                rc = build_update_attribute(object->template, CKA_EXTRACTABLE,
                                            (CK_BYTE *)&exp, sizeof(exp));
                if (rc != CKR_OK) {
                    TRACE_DEVEL("build_update_attribute(CKA_EXTRACTABLE) "
                                "failed\n");
                    return rc;
                }

#ifndef NO_PKEY
                rc = build_update_attribute(object->template,
                                            CKA_IBM_PROTKEY_EXTRACTABLE,
                                            (CK_BYTE *)&cpacf_exp,
                                            sizeof(cpacf_exp));
                if (rc != CKR_OK) {
                    TRACE_DEVEL("build_update_attribute(CKA_EXTRACTABLE) "
                                "failed\n");
                    return rc;
                }
#endif
            } else {
                TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_AES\n");
                return CKR_TEMPLATE_INCONSISTENT;
            }

            rc = build_update_attribute(object->template,
                                        CKA_IBM_CCA_AES_KEY_MODE,
                                        (CK_BYTE *)&mode, sizeof(mode));
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_update_attribute(CKA_IBM_CCA_AES_KEY_MODE) "
                            "failed\n");
                return rc;
            }
        } else {
            TRACE_DEBUG("Unknown/unsupported keytype in function %s line %d\n", __func__, __LINE__);
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, object->template,
                                        opaque_attr->pValue,
                                        opaque_attr->ulValueLen,
                                        new_mk, token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* create a dummy CKA_VALUE attribute with the key bit size but all zero */
        if ((rc = build_update_attribute(object->template, CKA_VALUE,
                                         zorro, token_keybitsize / 8))) {
            TRACE_DEVEL("build_update_attribute(CKA_VALUE) failed\n");
            return rc;
        }

        /* Add/update CKA_SENSITIVE */
        rc = build_update_attribute(object->template, CKA_SENSITIVE, &true, sizeof(CK_BBOOL));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for CKA_SENSITIVE failed. rc=0x%lx\n", rc);
            return rc;
        }

    } else {
        /*
         * This is an import of a clear key value which is to be transfered
         * into a CCA Data AES or DES key now.
         */

        long return_code, reason_code, rule_array_count;
        unsigned char target_key_token[CCA_MAX_AES_CIPHER_KEY_SIZE] = { 0 };
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
        CK_ATTRIBUTE *value_attr = NULL;
        long reserved_1 = 0, key_token_len = sizeof(target_key_token);
        long key_part_len;
        CK_IBM_CCA_AES_KEY_MODE_TYPE mode = CK_IBM_CCA_AES_DATA_KEY;

        rc = template_attribute_get_non_empty(object->template, CKA_VALUE,
                                              &value_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Incomplete key template\n");
            return CKR_TEMPLATE_INCOMPLETE;
        }

        if (keytype == CKK_AES) {
            rc = cca_get_and_set_aes_key_mode(tokdata, object->template, &mode);
            if (rc != CKR_OK) {
                TRACE_DEVEL("cca_get_and_set_aes_key_mode failed\n");
                return rc;
            }
        }

        if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
            memcpy(rule_array, "INTERNALAES     CIPHER  NO-KEY  ANY-MODE",
                   5 * CCA_KEYWORD_SIZE);
            rule_array_count = 5;

            rc = cca_aes_cipher_add_key_usage_keywords(tokdata,
                                                       object->template,
                                                       rule_array,
                                                       sizeof(rule_array),
                                                       (CK_ULONG *)
                                                           &rule_array_count);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to add key usage keywords\n");
                return rc;
            }

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &reserved_1, NULL,
                             &key_token_len, target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKTB2 (AES CIPHER KEY TOKEN BUILD) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }

            memcpy(rule_array, "AES     FIRST   MIN1PART",
                   3 * CCA_KEYWORD_SIZE);
            rule_array_count = 3;
            key_token_len = sizeof(target_key_token);
            key_part_len = value_attr->ulValueLen * 8;

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &key_part_len, value_attr->pValue,
                             &key_token_len, target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKPI2 (AES CIPHER KEY IMPORT FIRST) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }

            memcpy(rule_array, "AES     COMPLETE", 2 * CCA_KEYWORD_SIZE);
            rule_array_count = 2;

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                             &rule_array_count, rule_array,
                             &reserved_1, NULL,
                             &key_token_len, target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBKPI2 (AES CIPHER KEY IMPORT COMPLETE) failed."
                            " return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }
        } else {
            switch (keytype) {
            case CKK_AES:
                memcpy(rule_array, "AES     ", CCA_KEYWORD_SIZE);
                break;
            case CKK_DES:
            case CKK_DES3:
                memcpy(rule_array, "DES     ", CCA_KEYWORD_SIZE);
                break;
            default:
                return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }

            rule_array_count = 1;

            USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
                dll_CSNBCKM(&return_code, &reason_code, NULL, NULL,
                            &rule_array_count, rule_array,
                            (long int *)&value_attr->ulValueLen,
                            value_attr->pValue,
                            target_key_token);
            USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

            if (return_code != CCA_SUCCESS) {
                TRACE_ERROR("CSNBCKM failed. return:%ld, reason:%ld\n",
                            return_code, reason_code);
                return CKR_FUNCTION_FAILED;
            }
            key_token_len = CCA_KEY_ID_SIZE;
        }

        if (analyse_cca_key_token(target_key_token, key_token_len,
                                  &token_type, &token_keybitsize, &mkvp) == FALSE ||
            mkvp == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, object->template,
                                        target_key_token, key_token_len, new_mk,
                                        token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* Add the key object to the template */
        if ((rc = build_update_attribute(object->template, CKA_IBM_OPAQUE,
                                         target_key_token, key_token_len))) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
            return rc;
        }

        /* zero clear key value */
        OPENSSL_cleanse(value_attr->pValue, value_attr->ulValueLen);
    }

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(object->template);

    return CKR_OK;
}

static CK_RV import_generic_secret_key(STDLL_TokData_t *tokdata,
                                       OBJECT * object)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ULONG keylen, keybitlen;
    enum cca_token_type token_type;
    unsigned int token_payloadbitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk, exp, cpacf_exp;

    rc = template_attribute_find(object->template, CKA_VALUE, &value_attr);
    if (rc == FALSE) {
        TRACE_ERROR("Incomplete Generic Secret (HMAC) key template\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }
    keylen = value_attr->ulValueLen;
    keybitlen = 8 * keylen;

    /* key bit length needs to be 80-2048 bits */
    if (keybitlen < 80 || keybitlen > 2048) {
        TRACE_ERROR("HMAC key bit size of %lu not within CCA range (80-2048 bits)\n", keybitlen);
        return CKR_KEY_SIZE_RANGE;
    }

    rc = template_attribute_find(object->template, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure key which is stored in
         * the CKA_IBM_OPAQUE attribute. The CKA_VALUE attribute is only
         * a dummy reflecting the clear key byte size. However, let's
         * check if the template attributes match to the cca key in the
         * CKA_IBM_OPAQUE attribute.
         */
        unsigned int plbitsize;
        CK_BBOOL true = TRUE;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_payloadbitsize, &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (token_type != sec_hmac_key) {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to"
                        " keytype CKK_GENERIC_SECRET\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        rc = ccatok_var_sym_token_is_exportable(opaque_attr->pValue,
                                                opaque_attr->ulValueLen,
                                                &exp, &cpacf_exp);
        if (rc != CKR_OK)
            return rc;

        rc = build_update_attribute(object->template, CKA_EXTRACTABLE,
                                    (CK_BYTE *)&exp, sizeof(exp));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute(CKA_EXTRACTABLE) "
                        "failed\n");
            return rc;
        }

#ifndef NO_PKEY
        rc = build_update_attribute(object->template,
                                    CKA_IBM_PROTKEY_EXTRACTABLE,
                                    (CK_BYTE *)&cpacf_exp,
                                    sizeof(cpacf_exp));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute(CKA_EXTRACTABLE) "
                        "failed\n");
            return rc;
        }
#endif

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, object->template,
                                        opaque_attr->pValue,
                                        opaque_attr->ulValueLen,
                                        new_mk, token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* calculate expected payload size from the given keybitlen */
        plbitsize = (((keybitlen + 32) + 63) & (~63)) + 320;
        /* and check with the payload size within the cca hmac token */
        if (plbitsize != token_payloadbitsize) {
            TRACE_ERROR("CCA HMAC token payload size and keysize do not match\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* Add/update CKA_SENSITIVE */
        rc = build_update_attribute(object->template, CKA_SENSITIVE, &true, sizeof(CK_BBOOL));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for CKA_SENSITIVE failed. rc=0x%lx\n", rc);
            return rc;
        }

    } else {
        /*
         * This is an import of a clear key value which is to be transfered
         * into a CCA HMAC key now.
         */

        long return_code, reason_code, rule_array_count;
        unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0 };
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
        long key_name_len = 0, clr_key_len = 0;
        long user_data_len = 0, key_part_len = 0;
        long token_data_len = 0, verb_data_len = 0;
        long key_token_len = sizeof(key_token);
        CK_BBOOL extractable = TRUE;

        memcpy(rule_array, "INTERNALNO-KEY  HMAC    MAC     GENERATE",
               5 * CCA_KEYWORD_SIZE);
        rule_array_count = 5;

        rc = template_attribute_get_bool(object->template, CKA_EXTRACTABLE,
                                         &extractable);
        if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
            TRACE_ERROR("Failed to get CKA_EXTRACTABLE\n");
            return rc;
        }

        if (!extractable) {
            memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
                   "NOEX-SYMNOEXUASYNOEXAASYNOEX-DESNOEX-AESNOEX-RSA",
                   6 * CCA_KEYWORD_SIZE);
            rule_array_count += 6;
        }

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL,
                         &rule_array_count, rule_array,
                         &clr_key_len, NULL, &key_name_len, NULL,
                         &user_data_len, NULL, &token_data_len, NULL,
                         &verb_data_len, NULL, &key_token_len, key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBKTB2 (HMAC KEY TOKEN BUILD) failed."
                        " return:%ld, reason:%ld\n", return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        memcpy(rule_array, "HMAC    FIRST   MIN1PART", 3 * CCA_KEYWORD_SIZE);
        rule_array_count = 3;
        key_part_len = keylen * 8;
        key_token_len = sizeof(key_token);

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                         &rule_array_count, rule_array,
                         &key_part_len, value_attr->pValue,
                         &key_token_len, key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBKPI2 (HMAC KEY IMPORT FIRST) failed."
                        " return:%ld, reason:%ld\n", return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        memcpy(rule_array, "HMAC    COMPLETE", 2 * CCA_KEYWORD_SIZE);
        rule_array_count = 2;
        key_part_len = 0;
        key_token_len = sizeof(key_token);

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL,
                         &rule_array_count, rule_array,
                         &key_part_len, NULL, &key_token_len, key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBKPI2 (HMAC KEY IMPORT COMPLETE) failed."
                        " return:%ld, reason:%ld\n", return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        if (analyse_cca_key_token(key_token, key_token_len,
                                  &token_type, &token_payloadbitsize,
                                  &mkvp) == FALSE ||
            mkvp == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, object->template, key_token,
                                        key_token_len, new_mk, token_type,
                                        FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* Add the key object to the template */
        if ((rc = build_update_attribute(object->template, CKA_IBM_OPAQUE,
                                         key_token, key_token_len))) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
            return rc;
        }
    }

    /* zero clear key value */
    OPENSSL_cleanse(value_attr->pValue, value_attr->ulValueLen);

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(object->template);

    return CKR_OK;
}

static CK_RV build_private_EC_key_value_structure(CK_BYTE *privkey, CK_ULONG privlen,
        CK_BYTE *pubkey, CK_ULONG publen,
        uint8_t curve_type, uint16_t curve_bitlen,
        unsigned char *key_value_structure, long *key_value_structure_length)
{
    ECC_PAIR ecc_pair;

    ecc_pair.curve_type = curve_type;
    ecc_pair.reserved = 0x00;
    ecc_pair.p_bitlen = htobe16(curve_bitlen);
    ecc_pair.d_length = htobe16(privlen);

    /* Adjust public key if necessary: there may be an indication if the public
     * key is compressed, uncompressed, or hybrid. */
    if (publen == 2 * privlen + 1) {
        if (pubkey[0] == POINT_CONVERSION_UNCOMPRESSED ||
            pubkey[0] == POINT_CONVERSION_HYBRID ||
            pubkey[0] == POINT_CONVERSION_HYBRID+1) {
            /* uncompressed or hybrid EC public key */
            ecc_pair.q_length = htobe16(publen);
            memcpy(key_value_structure, &ecc_pair, sizeof(ECC_PAIR));
            memcpy(key_value_structure + sizeof(ECC_PAIR), privkey, privlen);
            memcpy(key_value_structure + sizeof(ECC_PAIR) + privlen, pubkey, publen);
            *key_value_structure_length = sizeof(ECC_PAIR) + privlen + publen;
        } else {
            TRACE_ERROR("Unsupported public key format\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }
    } else if (publen == 2 * privlen) {
        /* uncompressed or hybrid EC public key without leading indication */
        ecc_pair.q_length = htobe16(publen + 1);
        memcpy(key_value_structure, &ecc_pair, sizeof(ECC_PAIR));
        memcpy(key_value_structure + sizeof(ECC_PAIR), privkey, privlen);
        memset(key_value_structure + sizeof(ECC_PAIR) + privlen, POINT_CONVERSION_UNCOMPRESSED, 1);
        memcpy(key_value_structure + sizeof(ECC_PAIR) + privlen + 1, pubkey, publen);
        *key_value_structure_length = sizeof(ECC_PAIR) + privlen + 1 + publen;
    } else {
        TRACE_ERROR("Unsupported private/public key length (%ld,%ld)\n",privlen,publen);
        TRACE_ERROR("Compressed public keys are not supported by this token.\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    return CKR_OK;
}

static unsigned int bitlen2bytelen(uint16_t bitlen)
{
    if (bitlen != CURVE521)
        return bitlen / 8;

    return bitlen / 8 + 1;
}

static CK_RV build_public_EC_key_value_structure(CK_BYTE *pubkey, CK_ULONG publen,
        uint8_t curve_type, uint16_t curve_bitlen, int curve_nid,
        unsigned char *key_value_structure, long *key_value_structure_length)
{
    ECC_PUBL ecc_publ;
    CK_RV rc = CKR_OK;
    BN_CTX *ctx = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *bn_x = NULL, *bn_y = NULL;
    int y_bit;

    ecc_publ.curve_type = curve_type;
    ecc_publ.reserved = 0x00;
    ecc_publ.p_bitlen = htobe16(curve_bitlen);

    if (publen == 2 * bitlen2bytelen(curve_bitlen) + 1) {
        if (pubkey[0] == POINT_CONVERSION_UNCOMPRESSED ||
            pubkey[0] == POINT_CONVERSION_HYBRID ||
            pubkey[0] == POINT_CONVERSION_HYBRID+1) {
            /* uncompressed or hybrid EC public key */
            ecc_publ.q_length = htobe16(publen);
            memcpy(key_value_structure, &ecc_publ, sizeof(ECC_PUBL));
            memcpy(key_value_structure + sizeof(ECC_PUBL), pubkey, publen);
            *key_value_structure_length = sizeof(ECC_PUBL) + publen;
         } else {
             TRACE_ERROR("Unsupported public key format\n");
             return CKR_TEMPLATE_INCONSISTENT;
         }
    } else if (publen == 2 * bitlen2bytelen(curve_bitlen)) {
        /* uncompressed or hybrid EC public key without leading 0x04 */
        ecc_publ.q_length = htobe16(publen + 1);
        memcpy(key_value_structure, &ecc_publ, sizeof(ECC_PUBL));
        memset(key_value_structure + sizeof(ECC_PUBL), POINT_CONVERSION_UNCOMPRESSED, 1);
        memcpy(key_value_structure + sizeof(ECC_PUBL) + 1, pubkey, publen);
        *key_value_structure_length = sizeof(ECC_PUBL) + publen + 1;
    } else if (publen == bitlen2bytelen(curve_bitlen) + 1) {
        if (pubkey[0] != POINT_CONVERSION_COMPRESSED &&
            pubkey[0] != POINT_CONVERSION_COMPRESSED + 1) {
             TRACE_ERROR("Unsupported public key format\n");
             return CKR_TEMPLATE_INCONSISTENT;
        }

        /* Uncompress the EC point, CCA needs it uncompressed */

        ctx = BN_CTX_new();
        if (ctx == NULL) {
            TRACE_ERROR("BN_CTX_new failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        group = EC_GROUP_new_by_curve_name(curve_nid);
        if (group == NULL) {
            TRACE_ERROR("Curve %d is not supported by openssl. Cannot decompress "
                        "public key\n", curve_nid);
            return CKR_CURVE_NOT_SUPPORTED;
        }

        point = EC_POINT_new(group);
        if (point == NULL) {
            TRACE_ERROR("EC_POINT_new failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        bn_x = BN_bin2bn(pubkey + 1, bitlen2bytelen(curve_bitlen), NULL);
        bn_y = BN_new();
        if (bn_x == NULL || bn_y == NULL) {
            TRACE_ERROR("BN_bin2bn/BN_new failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        y_bit = (pubkey[0] == POINT_CONVERSION_COMPRESSED ? 0 : 1);
        if (!EC_POINT_set_compressed_coordinates(group, point, bn_x,
                                                 y_bit, ctx)) {
            TRACE_ERROR("EC_POINT_set_compressed_coordinates failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (!EC_POINT_is_on_curve(group, point, ctx)) {
            TRACE_ERROR("EC_POINT_is_on_curve failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (!EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y, ctx)) {
            TRACE_ERROR("EC_POINT_is_on_curve failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (BN_bn2binpad(bn_x, key_value_structure + sizeof(ECC_PUBL) + 1,
                         bitlen2bytelen(curve_bitlen)) <= 0 ||
            BN_bn2binpad(bn_y, key_value_structure + sizeof(ECC_PUBL) + 1 +
                               bitlen2bytelen(curve_bitlen),
                         bitlen2bytelen(curve_bitlen)) <= 0) {
            TRACE_ERROR("BN_bn2binpad failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        ecc_publ.q_length = htobe16(publen + bitlen2bytelen(curve_bitlen));
        memcpy(key_value_structure, &ecc_publ, sizeof(ECC_PUBL));
        memset(key_value_structure + sizeof(ECC_PUBL),
               POINT_CONVERSION_UNCOMPRESSED, 1);
        *key_value_structure_length = sizeof(ECC_PUBL) + be16toh(ecc_publ.q_length);
    } else {
        TRACE_ERROR("Unsupported public key length %ld\n",publen);
        return CKR_TEMPLATE_INCONSISTENT;
    }

done:
    if (ctx)
        BN_CTX_free(ctx);
    if (group)
        EC_GROUP_free(group);
    if (point)
        EC_POINT_free(point);
    if (bn_x)
        BN_free(bn_x);
    if (bn_y)
        BN_free(bn_y);

    return rc;
}

/* helper function, check cca ec type, keybits and add the CKA_EC_PARAMS attribute */
static CK_RV check_cca_ec_type_and_add_params(uint8_t cca_ec_type,
                                              uint16_t cca_ec_bits,
                                              TEMPLATE *templ)
{
    CK_RV rc;
    CK_ULONG i;

    for (i = 0; i < NUMEC; i++) {
        if ((der_ec_supported[i].curve_type == PRIME_CURVE ||
             der_ec_supported[i].curve_type == BRAINPOOL_CURVE ||
             der_ec_supported[i].curve_type == KOBLITZ_CURVE) &&
            !der_ec_supported[i].twisted &&
            der_ec_supported[i].curve_type == cca_ec_type &&
            der_ec_supported[i].prime_bits == cca_ec_bits) {
            rc = build_update_attribute(templ, CKA_EC_PARAMS,
                                        (CK_BYTE *)der_ec_supported[i].data,
                                        der_ec_supported[i].data_size);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_update_attribute(CKA_EC_PARAMS) failed\n");
                return rc;
            }

            return CKR_OK;
        }
    }

    TRACE_ERROR("CCA token type with unknown curve type %hhu or length %hu\n",
                cca_ec_type, cca_ec_bits);
    return CKR_ATTRIBUTE_VALUE_INVALID;
}

static CK_RV import_ec_privkey(STDLL_TokData_t *tokdata, TEMPLATE *priv_templ)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;
    enum cca_token_type token_type;
    unsigned int token_keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;
#ifndef NO_PKEY
    CK_BBOOL cpacf_exp;
#endif
    CK_BBOOL derive = FALSE;

    rc = template_attribute_find(priv_templ, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure ecc private key which
         * is stored in the CKA_IBM_OPAQUE attribute.
         */
        CK_BBOOL true = TRUE;
        CK_BYTE *t;
        struct cca_key_derivation_data *ecc_info;
        uint16_t priv_offset;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_keybitsize, &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (token_type != sec_ecc_priv_key) {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_EC\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

#ifndef NO_PKEY
        cpacf_exp = ccatok_ecc_token_is_cpacf_exportable(opaque_attr->pValue,
                                                         opaque_attr->ulValueLen);

        rc = build_update_attribute(priv_templ,
                                    CKA_IBM_PROTKEY_EXTRACTABLE,
                                    (CK_BYTE *)&cpacf_exp,
                                    sizeof(cpacf_exp));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute(CKA_EXTRACTABLE) "
                        "failed\n");
            return rc;
        }
#endif /* NO_PKEY */

        /*
         * The CCA token only supports to derive DATA and CIPHER keys. So if
         * the ECC private key token has an ECC key derivation info section, the
         * to-be-derived key type must be DATA or CIPHER.
         * Furthermore, check if CKA_DERIVE is TRUE. If so, the ECC private key
         * token must have an ECC key derivation info section (requires V1 ECC
         * key token), and must have been generated by random (see pedigree/
         * key-source field).
         */
        ecc_info = cca_ec_ecc_key_derivation_info(opaque_attr->pValue);
        if (ecc_info != NULL &&
            ecc_info->key_algorithm != CCA_AES_KEY &&
            ecc_info->key_type != CCA_KEY_DERIVE_TYPE_DATA &&
            ecc_info->key_type != CCA_KEY_DERIVE_TYPE_CIPHER) {
            TRACE_ERROR("ECC private key has an ECC key derivation info section "
                        "(X'23'), but the key type is not AES DATA or "
                        "AES CIPHER\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        rc = template_attribute_get_bool(priv_templ, CKA_DERIVE, &derive);
        if (rc == CKR_OK && derive == TRUE) {
            if (ecc_info == NULL) {
                TRACE_ERROR("CKA_DERIVE is TRUE, but ECC private key does not "
                            "have an ECC key derivation info section (X'23')\n");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }

            priv_offset = cca_ec_privkey_offset(opaque_attr->pValue);
            if (((CK_BYTE *)opaque_attr->pValue)[priv_offset +
                         CCA_EC_INTTOK_PRIVKEY_KEY_SOURCE_OFFSET] !=
                                    CCA_EC_INTTOK_PRIVKEY_KEY_SOURCE_RANDOM) {
                TRACE_ERROR("CKA_DERIVE is TRUE, but ECC private key was not "
                            "generated by random\n");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }

        rc = cca_reencipher_created_key(tokdata, priv_templ,
                                        opaque_attr->pValue,
                                        opaque_attr->ulValueLen,
                                        new_mk, token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* check curve and add CKA_EC_PARAMS attribute */
        t = opaque_attr->pValue;
        rc = check_cca_ec_type_and_add_params(t[8+9], token_keybitsize, priv_templ);
        if (rc != CKR_OK)
            return rc;

        /* Add/update CKA_SENSITIVE */
        rc = build_update_attribute(priv_templ, CKA_SENSITIVE, &true, sizeof(CK_BBOOL));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for CKA_SENSITIVE failed. rc=0x%lx\n", rc);
            return rc;
        }

    } else {
        /*
         * This is an import of a clear ecc private key which is to be transfered
         * into a CCA ECC private key.
         */

        long private_key_name_length, key_token_length, target_key_token_length;
        long return_code, reason_code, rule_array_count, exit_data_len = 0;
        long key_value_structure_length, param1=0;
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
        unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
        unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
        unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
        unsigned char target_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        unsigned char *exit_data = NULL;
        unsigned char *param2=NULL;
        CK_BYTE *privkey = NULL, *pubkey = NULL;
        CK_ATTRIBUTE *attr = NULL;
        CK_ULONG privlen = 0, publen = 0;
        uint8_t curve_type;
        uint16_t curve_bitlen;
        int curve_nid;

        /* Check if curve supported and determine curve type and bitlen */
        rc = curve_supported(tokdata, priv_templ, &curve_type, &curve_bitlen,
                             &curve_nid);
        if (rc != CKR_OK) {
            TRACE_ERROR("Curve not supported by this token.\n");
            return rc;
        }

        /*
         * Check if CKA_DERIVE is TRUE. An ECC key imported from clear text
         * can not be used for ECDH. CCA allows ECDH only for randomly
         * generated keys.
         */
        rc = template_attribute_get_bool(priv_templ, CKA_DERIVE, &derive);
        if (rc == CKR_OK && derive == TRUE) {
            TRACE_ERROR("CKA_DERIVE is TRUE. CCA does not allow ECDH key "
                        "derivation with keys imported from clear\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* Find private key data in template */
        rc = template_attribute_get_non_empty(priv_templ, CKA_VALUE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            return rc;
        }

        privlen = attr->ulValueLen;
        privkey = attr->pValue;

        /* calculate the public key from the private key */
        rc = template_attribute_get_non_empty(priv_templ, CKA_ECDSA_PARAMS,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the key.\n");
            return rc;
        }

        rc = ec_point_from_priv_key(attr->pValue, attr->ulValueLen,
                                    privkey, privlen, &pubkey, &publen);
        if (rc != CKR_OK) {
            TRACE_ERROR("ec_point_from_priv_key failed.\n");
            return rc;
        }

        /* Build key_value_structure */
        memset(key_value_structure, 0, CCA_KEY_VALUE_STRUCT_SIZE);

        rc = build_private_EC_key_value_structure(privkey, privlen,
                                                  pubkey, publen, curve_type, curve_bitlen,
                                                  (unsigned char *)&key_value_structure,
                                                  &key_value_structure_length);
        free(pubkey);
        if (rc != CKR_OK)
            return rc;

        /*
         * Build key token.
         * An ECC key imported from clear text can not be used for ECDH.
         * CCA allows ECDH only for randomly generated keys.
         * Thus no need for keywords KEY-MGMT and ECC-VER1 here.
         */
        rule_array_count = 1;
        memcpy(rule_array, "ECC-PAIR", (size_t)(CCA_KEYWORD_SIZE));
        private_key_name_length = 0;
        key_token_length = CCA_KEY_TOKEN_SIZE;
        key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;

#ifndef NO_PKEY
        /* Add protected key related attributes to the rule array */
        rc = ccatok_pkey_add_attrs(tokdata, priv_templ, CKK_EC, curve_type,
                                   curve_bitlen, 0, rule_array, sizeof(rule_array),
                                   (CK_ULONG *)&rule_array_count);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s ccatok_pkey_add_attrs failed with rc=0x%lx\n", __func__, rc);
            return rc;
        }
#endif /* NO_PKEY */

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKB(&return_code, &reason_code,
                        &exit_data_len, exit_data,
                        &rule_array_count, rule_array,
                        &key_value_structure_length, key_value_structure,
                        &private_key_name_length, private_key_name,
                        &param1, param2, &param1, param2, &param1, param2,
                        &param1, param2, &param1, param2,
                        &key_token_length,
                        key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKB (EC KEY TOKEN BUILD) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
            if (is_curve_error(return_code, reason_code))
                return CKR_CURVE_NOT_SUPPORTED;
            return CKR_FUNCTION_FAILED;
        }

        /* Now import the PKA key token */
        rule_array_count = 1;
        memcpy(rule_array, "ECC     ", (size_t)(CCA_KEYWORD_SIZE));
        key_token_length = CCA_KEY_TOKEN_SIZE;
        target_key_token_length = CCA_KEY_TOKEN_SIZE;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKI(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        &key_token_length, key_token,
                        transport_key_identifier,
                        &target_key_token_length, target_key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKI (EC KEY TOKEN IMPORT) failed." " return:%ld, reason:%ld\n",
                        return_code, reason_code);
            if (is_curve_error(return_code, reason_code))
                return CKR_CURVE_NOT_SUPPORTED;
            return CKR_FUNCTION_FAILED;
        }

        if (analyse_cca_key_token(target_key_token, target_key_token_length,
                                  &token_type, &token_keybitsize,
                                  &mkvp) == FALSE ||
            mkvp == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, priv_templ, target_key_token,
                                        target_key_token_length, new_mk,
                                        token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* Add key token to template as CKA_IBM_OPAQUE */
        if ((rc = build_update_attribute(priv_templ, CKA_IBM_OPAQUE,
                                         target_key_token, target_key_token_length))) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
            return rc;
        }

        /* zero clear key values */
        OPENSSL_cleanse(privkey, privlen);
    }

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(priv_templ);

    return CKR_OK;
}

static CK_RV import_ec_pubkey(STDLL_TokData_t *tokdata, TEMPLATE *pub_templ)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;

    rc = template_attribute_find(pub_templ, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure ecc public key which
         * is stored in the CKA_IBM_OPAQUE attribute.
         */
        enum cca_token_type token_type;
        unsigned int token_keybitsize;
        const CK_BYTE *mkvp;
        CK_BYTE *t, *q;
        uint16_t q_len;
        CK_BYTE *ecpoint = NULL;
        CK_ULONG ecpoint_len;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_keybitsize, &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (token_type != sec_ecc_publ_key) {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to keytype CKK_EC\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* check curve and add CKA_EC_PARAMS attribute */
        t = opaque_attr->pValue;
        rc = check_cca_ec_type_and_add_params(t[8+8], token_keybitsize, pub_templ);
        if (rc != CKR_OK)
            return rc;

        /* we need to add the CKA_EC_POINT attribute */
        q = (CK_BYTE *)(t + 8 + 14);
        q_len = be16toh(*((uint16_t *)(t + 8 + 12)));
        if (q_len > CCATOK_EC_MAX_Q_LEN) {
            TRACE_ERROR("Invalid Q len %hu\n", q_len);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        rc = ber_encode_OCTET_STRING(FALSE, &ecpoint, &ecpoint_len, q, q_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
            return rc;
        }
        rc = build_update_attribute(pub_templ, CKA_EC_POINT, ecpoint, ecpoint_len);
        free(ecpoint);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute(CKA_EC_POINT) failed\n");
            return rc;
        }

    } else {
        /*
         * This is an import of a clear ecc public key which is to be transfered
         * into a CCA ECC public key.
         */

        long return_code, reason_code, rule_array_count, exit_data_len = 0;
        long private_key_name_length, key_token_length;
        unsigned char *exit_data = NULL;
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
        long key_value_structure_length;
        unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
        unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
        unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        long param1=0;
        unsigned char *param2=NULL;
        uint8_t curve_type;
        uint16_t curve_bitlen;
        int curve_nid;
        CK_BYTE *pubkey = NULL;
        CK_ULONG publen = 0;
        CK_ATTRIBUTE *attr = NULL;
        CK_ULONG field_len;

        /* Check if curve supported and determine curve type and bitlen */
        rc = curve_supported(tokdata, pub_templ, &curve_type, &curve_bitlen,
                             &curve_nid);
        if (rc != CKR_OK) {
            TRACE_ERROR("Curve not supported by this token.\n");
            return rc;
        }

        /* Find public key data as BER encoded OCTET STRING in template */
        rc = template_attribute_get_non_empty(pub_templ, CKA_EC_POINT, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_EC_POINT for the key.\n");
            return rc;
        }

        rc = ber_decode_OCTET_STRING(attr->pValue, &pubkey, &publen,
                                     &field_len);
        if (rc != CKR_OK || attr->ulValueLen != field_len) {
            TRACE_DEVEL("ber decoding of public key failed\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        /* Build key_value_structure */
        memset(key_value_structure, 0, CCA_KEY_VALUE_STRUCT_SIZE);

        rc = build_public_EC_key_value_structure(pubkey, publen,
                                                 curve_type, curve_bitlen,
                                                 curve_nid,
                                                 (unsigned char *)&key_value_structure,
                                                 &key_value_structure_length);
        if (rc != CKR_OK)
            return rc;

        /* Build public key token */
        rule_array_count = 1;
        memcpy(rule_array, "ECC-PUBL", (size_t)(CCA_KEYWORD_SIZE));
        private_key_name_length = 0;
        key_token_length = CCA_KEY_TOKEN_SIZE;
        key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKB(&return_code, &reason_code,
                        &exit_data_len, exit_data,
                        &rule_array_count, rule_array,
                        &key_value_structure_length, key_value_structure,
                        &private_key_name_length, private_key_name,
                        &param1, param2, &param1, param2, &param1, param2,
                        &param1, param2, &param1, param2,
                        &key_token_length,
                        key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKB (EC KEY TOKEN BUILD) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
            if (is_curve_error(return_code, reason_code))
                return CKR_CURVE_NOT_SUPPORTED;
            return CKR_FUNCTION_FAILED;
        }

        /* Public keys do not need to be wrapped, so just add public
           key token to template as CKA_IBM_OPAQUE */
        if ((rc = build_update_attribute(pub_templ, CKA_IBM_OPAQUE,
                                         key_token, key_token_length))) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
            return rc;
        }
    }

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(pub_templ);

    return CKR_OK;
}

/*
 * ECDH key derivation.
 * CCA requires that the ECC private key used for ECDH with keyword DERIV02
 * has an ECC key derivation section (X'23') that contains the type and size
 * of keys that can be derived with that key.
 * The CCA token generates or imports ECC keys with an ECC key derivation
 * section allowing to derive AES keys only. Thus, the derivation is restricted
 * to just that one key type and size that is contained in the private key's
 * ECC key derivation section.
 * For ECC key generation, the to be derived key type and size can be specified
 * using the CKA_DERIVE_TEMPLATE containing CKA_KEY_TYPE, CKA_VALUE_LEN and
 * CKA_IBM_CCA_AES_KEY_MODE. This information will then be added as ECC key
 * derivation section to the private key. The default derivation key type and
 * size is is AES-256. The default CCA key mode is determined by the global
 * configuration setting.
 * Furthermore, CCA allows ECDH key derivation with keyword DERIV02 only
 * with ECC private keys that were generated by random. Keys imported from
 * clear can not be used for ECDH.
 */
CK_RV token_specific_ecdh_pkcs_derive_kdf(STDLL_TokData_t *tokdata,
                                          SESSION *session,
                                          OBJECT *base_key_obj,
                                          CK_ECDH1_DERIVE_PARAMS *params,
                                          OBJECT *derived_key_obj,
                                          CK_ULONG derived_key_class,
                                          CK_ULONG derived_key_type)
{
    long return_code, reason_code, rule_array_count, exit_data_len = 0;
    long private_key_name_length, pubkey_token_length, param1 = 0;
    unsigned char *exit_data = NULL;
    unsigned char *param2 = NULL;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long key_value_structure_length, key_bit_length;
    unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
    unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
    unsigned char pubkey_token[CCA_KEY_TOKEN_SIZE] = { 0, };
    unsigned char symkey_token[CCA_MAX_AES_CIPHER_KEY_SIZE] = { 0, };
    CK_ULONG symkey_token_size = sizeof(symkey_token);
    long symkey_token_length = sizeof(symkey_token);
    long shared_data_length, privkey_token_length;
    CK_ATTRIBUTE *opaque_attr;
    CK_ULONG base_key_class, base_key_type, key_len = 0;
    struct cca_key_derivation_data *ecc_info;
    CK_BYTE dummy[AES_KEY_SIZE_256] = { 0, };
    CK_IBM_CCA_AES_KEY_MODE_TYPE key_mode;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;
    uint8_t curve_type;
    uint16_t curve_bitlen;
    int curve_nid;
    CK_ULONG privlen;
    CK_BBOOL allocated = FALSE;
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len;
    CK_RV rc;

    UNUSED(session);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    /* Check the ECDH params */
    if (params->pPublicData == NULL || params->ulPublicDataLen == 0 ||
        (params->ulSharedDataLen >0 && params->pSharedData == NULL)) {
        TRACE_ERROR("Invalid mechanism parameter\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    switch (params->kdf) {
        case CKD_SHA224_KDF:
        case CKD_SHA256_KDF:
        case CKD_SHA384_KDF:
        case CKD_SHA512_KDF:
            break;
        default:
            TRACE_ERROR("CCA does not support KDFs other than "
                        "SHA224/256/384/512\n");
            return CKR_MECHANISM_PARAM_INVALID;
    }

    if (params->ulSharedDataLen > 256) {
        TRACE_ERROR("CCA does not support shared data > 256 bytes\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Get private key token */
    rc = template_attribute_get_non_empty(base_key_obj->template,
                                          CKA_IBM_OPAQUE, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    /* Check base key: must be an EC private key */
    if (!template_get_class(base_key_obj->template,
                            &base_key_class, &base_key_type)) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (base_key_class != CKO_PRIVATE_KEY || base_key_type != CKK_EC) {
        TRACE_ERROR("Base key is not an EC private key\n");
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Check the EC curve used */
    rc = curve_supported(tokdata, base_key_obj->template,
                         &curve_type, &curve_bitlen, &curve_nid);
    if (rc != CKR_OK) {
        TRACE_ERROR("Curve not supported\n");
        return rc;
    }

    rc = get_ecsiglen(base_key_obj, &privlen);
    privlen /= 2;

    if (derived_key_class != CKO_SECRET_KEY || derived_key_type != CKK_AES) {
        TRACE_ERROR("CCA can not derive keys of type other than AES\n");
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Must have a ECC key derivation info section */
    ecc_info = cca_ec_ecc_key_derivation_info(opaque_attr->pValue);
    if (ecc_info == NULL) {
        TRACE_ERROR("ECC private key does not have an ECC key derivation info "
                    "section X'23'\n");
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    /* Check the derived key: Must match the ECC key derivation info */
    if (ecc_info->key_algorithm != CCA_AES_KEY &&
        ecc_info->key_type != CCA_KEY_DERIVE_TYPE_DATA &&
        ecc_info->key_type != CCA_KEY_DERIVE_TYPE_CIPHER) {
        TRACE_ERROR("The EC private key can not derive keys other than AES "
                    "DATA or AES CIPHER key tokens\n");
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    rc = template_attribute_get_ulong(derived_key_obj->template,
                                      CKA_VALUE_LEN, &key_len);
    if (rc == CKR_TEMPLATE_INCOMPLETE)
        key_len = privlen; /* curve can derive that many bytes */
    else if (rc != CKR_OK)
        return rc;

    if (key_len != ecc_info->key_size / 8) {
        TRACE_ERROR("The EC private key can not derive keys of type other than "
                    "AES-%u\n", ecc_info->key_size);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    rc = template_attribute_get_ulong(derived_key_obj->template,
                                      CKA_IBM_CCA_AES_KEY_MODE, &key_mode);
    if (rc == CKR_OK) {
        switch (key_mode) {
        case CK_IBM_CCA_AES_DATA_KEY:
            if (ecc_info->key_type != CCA_KEY_DERIVE_TYPE_DATA) {
                TRACE_ERROR("The EC private key can not derive keys "
                            "other than AES DATA keys\n");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            break;
        case CK_IBM_CCA_AES_CIPHER_KEY:
            if (ecc_info->key_type != CCA_KEY_DERIVE_TYPE_CIPHER) {
                TRACE_ERROR("The EC private key can not derive keys "
                            "other than AES CIPHER keys\n");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    /* Get the public key as CCA key token */
    rc = ec_point_from_public_data(params->pPublicData,
                                   params->ulPublicDataLen,
                                   privlen, TRUE, &allocated,
                                   &ecpoint, &ecpoint_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ec_point_from_public_data failed\n");
        return rc;
    }

    memset(key_value_structure, 0, CCA_KEY_VALUE_STRUCT_SIZE);
    rc = build_public_EC_key_value_structure(ecpoint, ecpoint_len,
                                             curve_type, curve_bitlen,
                                             curve_nid,
                                             (unsigned char *)
                                                     &key_value_structure,
                                             &key_value_structure_length);
    if (rc != CKR_OK)
        goto done;

    /* Build public key token */
    rule_array_count = 1;
    memcpy(rule_array, "ECC-PUBL", CCA_KEYWORD_SIZE);
    private_key_name_length = 0;
    pubkey_token_length = CCA_KEY_TOKEN_SIZE;
    key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDPKB(&return_code, &reason_code,
                    &exit_data_len, exit_data,
                    &rule_array_count, rule_array,
                    &key_value_structure_length, key_value_structure,
                    &private_key_name_length, private_key_name,
                    &param1, param2, &param1, param2, &param1, param2,
                    &param1, param2, &param1, param2,
                    &pubkey_token_length,
                    pubkey_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDPKB (EC KEY TOKEN BUILD) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        if (is_curve_error(return_code, reason_code))
            rc = CKR_CURVE_NOT_SUPPORTED;
        else
            rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Build the output key skeleton */
    if (ecc_info->key_type != CCA_KEY_DERIVE_TYPE_DATA) {
        key_mode = CK_IBM_CCA_AES_DATA_KEY;
        rc = cca_build_aes_cipher_token(tokdata, derived_key_obj->template,
                                        symkey_token, &symkey_token_size);
    } else {
        key_mode = CK_IBM_CCA_AES_DATA_KEY;
        rc = cca_build_aes_data_token(tokdata, key_len,
                                      symkey_token, &symkey_token_size);
    }
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build CCA key token");
        goto done;
    }

    /* Build rule array for CSNDEDH */
    rule_array_count = 3;
    memcpy(rule_array, "DERIV02 KEY-AES ", 2 * CCA_KEYWORD_SIZE);

    switch (params->kdf) {
        case CKD_SHA224_KDF:
            memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "SHA-224 ",
                   (size_t)(CCA_KEYWORD_SIZE));
            break;
        case CKD_SHA256_KDF:
            memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "SHA-256 ",
                   (size_t)(CCA_KEYWORD_SIZE));
            break;
        case CKD_SHA384_KDF:
            memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "SHA-384 ",
                   (size_t)(CCA_KEYWORD_SIZE));
            break;
        case CKD_SHA512_KDF:
            memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "SHA-512 ",
                   (size_t)(CCA_KEYWORD_SIZE));
            break;
        default:
            TRACE_ERROR("CCA does not support KDFs other than "
                        "SHA224/256/384/512\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
    }

    key_bit_length = key_len * 8;

    shared_data_length = params->ulSharedDataLen;
    privkey_token_length = opaque_attr->ulValueLen;

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNDEDH(&return_code,
                    &reason_code,
                    &exit_data_len,
                    exit_data,
                    &rule_array_count,
                    rule_array,
                    &privkey_token_length, opaque_attr->pValue,
                    &param1, param2,
                    &pubkey_token_length, pubkey_token,
                    &param1, param2,
                    &shared_data_length, params->pSharedData,
                    &key_bit_length,
                    &param1, param2, &param1, param2,
                    &param1, param2, &param1, param2,
                    &param1, param2, &param1, param2,
                    &symkey_token_length, symkey_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDEDH (EC Diffie-Hellman) failed. return:%ld,"
                    " reason:%ld\n", return_code, reason_code);
        rc = CKR_FUNCTION_FAILED;
        if (return_code == 8 &&
            reason_code >= 2243 && reason_code <= 2246)
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        if (return_code == 8 && reason_code == 90)
            rc = CKR_FUNCTION_CANCELED; /* Control point prohibits function */
        goto done;
    }

    if (analyse_cca_key_token(symkey_token, symkey_token_length,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been unwrapped\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto done;
    }

    rc = cca_reencipher_created_key(tokdata, derived_key_obj->template,
                                    symkey_token, symkey_token_length,
                                    new_mk, keytype, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        goto done;
    }

    /* Add CKA_IBM_OPAQUE */
    rc = build_update_attribute(derived_key_obj->template, CKA_IBM_OPAQUE,
                                symkey_token, symkey_token_length);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto done;
    }

    /* Add CKA_VALUE as all zeros */
    rc = build_update_attribute(derived_key_obj->template, CKA_VALUE,
                                dummy, key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto done;
    }

    /* Add CKA_VALUE_LEN */
    rc = build_update_attribute(derived_key_obj->template, CKA_VALUE_LEN,
                                (CK_BYTE *)&key_len, sizeof(key_len));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto done;
    }

    /* Add CKA_IBM_CCA_AES_KEY_MODE */
    rc = build_update_attribute(derived_key_obj->template,
                                CKA_IBM_CCA_AES_KEY_MODE,
                                (CK_BYTE *)&key_mode, sizeof(key_mode));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto done;
    }

done:
    if (allocated && ecpoint != NULL)
        free(ecpoint);

    return rc;
}

static CK_RV build_ibm_dilithium_import_key_value_struct(
                                        CK_BBOOL private_key,
                                        const struct pqc_oid *oid,
                                        TEMPLATE *templ,
                                        unsigned char *key_value_structure,
                                        long *key_value_structure_length)
{
    CK_RV rc;
    uint8_t clear_format;
    uint16_t clear_len;
    long ofs = *key_value_structure_length;
    CK_ULONG len;

    rc = build_ibm_dilithium_key_value_struct(oid, key_value_structure, &ofs);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_ibm_dilithium_key_value_struct failed: 0x%lx\n", rc);
        return rc;
    }

    clear_format = private_key ? CCA_QSA_CLEAR_FORMAT_KAT :
                                 CCA_QSA_CLEAR_FORMAT_PUB_ONLY;
    memcpy(&key_value_structure[CCA_PKB_QSA_CLEAR_FORMAT_OFFSET], &clear_format,
           sizeof(uint8_t));

    if (private_key) {
        len = *key_value_structure_length - ofs;
        rc = ibm_dilithium_pack_priv_key(templ, oid, key_value_structure + ofs,
                                         &len);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_dilithium_pack_priv_key failed: 0x%lx\n", rc);
            return rc;
        }

        ofs += len;
    }

    len = *key_value_structure_length - ofs;
    rc = ibm_dilithium_pack_pub_key(templ, oid, key_value_structure + ofs,
                                     &len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_pack_pub_key failed: 0x%lx\n", rc);
        return rc;
    }

    ofs += len;

    clear_len = htobe16(ofs - CCA_QSA_KEY_VALUE_STRUCT_SIZE);
    memcpy(key_value_structure + CCA_PKB_QSA_CLEAR_LEN_OFFSET,
               &clear_len, sizeof(uint16_t));

    *key_value_structure_length = ofs;

    return CKR_OK;
}

static const struct pqc_oid *get_pqc_oid_from_algo_info(uint8_t algo_id,
                                                        uint16_t algo_params)
{
    CK_ULONG keyform = 0;

    switch (algo_id) {
    case CCA_QSA_ALGO_DILITHIUM_ROUND_2:
        switch (algo_params) {
        case CCA_QSA_ALGO_DILITHIUM_65:
            keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_65;
            break;
        case CCA_QSA_ALGO_DILITHIUM_87:
            keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_87;
            break;
        }
        break;
    case CCA_QSA_ALGO_DILITHIUM_ROUND_3:
        switch (algo_params) {
        case CCA_QSA_ALGO_DILITHIUM_65:
            keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_65;
            break;
        case CCA_QSA_ALGO_DILITHIUM_87:
            keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_87;
            break;
        }
        break;
    }

    return find_pqc_by_keyform(dilithium_oids, keyform);
}

static CK_RV import_ibm_dilithium_privkey(STDLL_TokData_t *tokdata,
                                          TEMPLATE *priv_templ)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;
    const struct pqc_oid *oid = NULL;
    enum cca_token_type token_type;
    unsigned int token_keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;

    rc = template_attribute_find(priv_templ, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure QSA private key which
         * is stored in the CKA_IBM_OPAQUE attribute.
         */
        CK_BBOOL true = TRUE;
        uint8_t algo_id;
        uint16_t privsec_len, pubsec_len, algo_params, rho_len, t1_len;
        CK_BYTE *t, *pub;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_keybitsize,
                                  &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE "
                        "attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (token_type != sec_qsa_priv_key) {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to "
                        "keytype CKK_IBM_PQC_DILITHIUM\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, priv_templ,
                                        opaque_attr->pValue,
                                        opaque_attr->ulValueLen,
                                        new_mk, token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* check dilithium variant and add keyform and mode attributes */
        t = opaque_attr->pValue;
        privsec_len = be16toh(*((uint16_t *)
                                    (t + CCA_QSA_INTTOK_PRIVKEY_OFFSET + 2)));
        if (CCA_QSA_INTTOK_PRIVKEY_OFFSET + privsec_len +
                CCA_QSA_EXTTOK_PUBLKEY_OFFSET > (int)opaque_attr->ulValueLen) {
            TRACE_DEVEL("CCA QSA key token has invalid priv section len or "
                        "token size\n");
            return CKR_FUNCTION_FAILED;
        }
        pub = t + CCA_QSA_INTTOK_PRIVKEY_OFFSET + privsec_len;
        pubsec_len = be16toh(*((uint16_t *)(pub + 2)));
        if (CCA_QSA_INTTOK_PRIVKEY_OFFSET + privsec_len +
                                 pubsec_len > (int)opaque_attr->ulValueLen) {
            TRACE_DEVEL("CCA QSA key token has invalid pub section len or "
                        "token size\n");
            return CKR_FUNCTION_FAILED;
        }

        algo_id = t[CCA_QSA_INTTOK_PRIVKEY_OFFSET +
                                        CCA_QSA_INTTOK_ALGO_ID_OFFSET];
        algo_params = be16toh(*((uint16_t *)(t + CCA_QSA_INTTOK_PRIVKEY_OFFSET +
                              CCA_QSA_INTTOK_ALGO_PARAMS_OFFSET)));

        oid = get_pqc_oid_from_algo_info(algo_id, algo_params);
        if (oid == NULL) {
            TRACE_ERROR("Invalid/unknown algorithm ID in CCA QSA token\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (!cca_pqc_strength_supported(tokdata, CKM_IBM_DILITHIUM,
                                        oid->keyform)) {
            TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                        oid->keyform);
            return CKR_KEY_SIZE_RANGE;
        }

        rc = ibm_pqc_add_keyform_mode(priv_templ, oid, CKM_IBM_DILITHIUM);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
            return rc;
        }

        /* Extract RHO and T1 attributes */
        rho_len = be16toh(*((uint16_t *)(pub + CCA_QSA_EXTTOK_RHO_OFFSET)));
        t1_len = be16toh(*((uint16_t *)(pub + CCA_QSA_EXTTOK_T1_OFFSET)));

        rc = build_update_attribute(priv_templ, CKA_IBM_DILITHIUM_RHO,
                                    pub + CCA_QSA_EXTTOK_PAYLOAD_OFFSET,
                                    rho_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_update_attribute (RHO) failed\n");
            return rc;
        }

        rc = build_update_attribute(priv_templ, CKA_IBM_DILITHIUM_T1,
                                    pub + CCA_QSA_EXTTOK_PAYLOAD_OFFSET +
                                                                rho_len,
                                    t1_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_update_attribute (T1) failed\n");
            return rc;
        }

        /* Add/update CKA_SENSITIVE */
        rc = build_update_attribute(priv_templ, CKA_SENSITIVE, &true,
                                    sizeof(CK_BBOOL));
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_update_attribute for CKA_SENSITIVE failed. "
                        "rc=0x%lx\n", rc);
            return rc;
        }
    } else {
        /*
         * This is an import of a clear IBM dilithium private key which is to be
         * transferred into a CCA QSA private key.
         */

        long private_key_name_length, key_token_length, target_key_token_length;
        long return_code, reason_code, rule_array_count, exit_data_len = 0;
        long key_value_structure_length, param1=0;
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
        unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
        unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
        unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
        unsigned char target_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        unsigned char *exit_data = NULL;
        unsigned char *param2 = NULL;
        CK_ATTRIBUTE *attr = NULL;

        /* A clear IBM Dilithium key must either have a CKA_VALUE containing
         * the PKCS#8 encoded private key, or must have a keyform/mode value
         * and the individual attributes
         */
        if (template_attribute_find(priv_templ, CKA_VALUE, &attr) == TRUE &&
            attr->ulValueLen > 0 && attr->pValue != NULL) {
            /* Private key in PKCS#8 form is present in CKA_VALUE */
            rc = ibm_dilithium_priv_unwrap(priv_templ, attr->pValue,
                                           attr->ulValueLen, FALSE);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to decode private key from CKA_VALUE.\n");
                return rc;
            }
        }

        oid = ibm_pqc_get_keyform_mode(priv_templ, CKM_IBM_DILITHIUM);
        if (oid == NULL) {
            TRACE_ERROR("%s Failed to determine dilithium OID\n", __func__);
            return CKR_TEMPLATE_INCOMPLETE;
        }

        if (!cca_pqc_strength_supported(tokdata, CKM_IBM_DILITHIUM,
                                        oid->keyform)) {
            TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                        oid->keyform);
            return CKR_KEY_SIZE_RANGE;
        }

        rc = ibm_pqc_add_keyform_mode(priv_templ, oid, CKM_IBM_DILITHIUM);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
            return rc;
        }

        /* Build key_value_structure */
        key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
        rc = build_ibm_dilithium_import_key_value_struct(
                                TRUE, oid, priv_templ,
                                (unsigned char *)&key_value_structure,
                                &key_value_structure_length);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_ibm_dilithium_import_key_value_struct failed: "
                        "0x%lx\n", rc);
            return rc;
        }

        /* Build key token */
        rule_array_count = 2;
        memcpy(rule_array, "QSA-PAIRU-DIGSIG", (size_t)(CCA_KEYWORD_SIZE * 2));
        private_key_name_length = 0;
        key_token_length = CCA_KEY_TOKEN_SIZE;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKB(&return_code, &reason_code,
                        &exit_data_len, exit_data,
                        &rule_array_count, rule_array,
                        &key_value_structure_length, key_value_structure,
                        &private_key_name_length, private_key_name,
                        &param1, param2, &param1, param2, &param1, param2,
                        &param1, param2, &param1, param2,
                        &key_token_length,
                        key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKB (QSA KEY TOKEN BUILD) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        /* Now import the PKA key token */
        rule_array_count = 1;
        memcpy(rule_array, "QSA     ", (size_t)(CCA_KEYWORD_SIZE));
        key_token_length = CCA_KEY_TOKEN_SIZE;
        target_key_token_length = CCA_KEY_TOKEN_SIZE;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKI(&return_code, &reason_code, NULL, NULL,
                        &rule_array_count, rule_array,
                        &key_token_length, key_token,
                        transport_key_identifier,
                        &target_key_token_length, target_key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKI (QSA KEY TOKEN IMPORT) failed. "
                        "return:%ld, reason:%ld\n",
                        return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        if (analyse_cca_key_token(target_key_token, target_key_token_length,
                                  &token_type, &token_keybitsize,
                                  &mkvp) == FALSE ||
            mkvp == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, token_type, mkvp, &new_mk) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        rc = cca_reencipher_created_key(tokdata, priv_templ, target_key_token,
                                        target_key_token_length, new_mk,
                                        token_type, FALSE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        /* Add key token to template as CKA_IBM_OPAQUE */
        if ((rc = build_update_attribute(priv_templ, CKA_IBM_OPAQUE,
                                         target_key_token,
                                         target_key_token_length))) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
            return rc;
        }

        /* zeroize key values */
        if (attr != NULL && attr->pValue != NULL && attr->ulValueLen > 0)
            OPENSSL_cleanse(attr->pValue, attr->ulValueLen);
        cleanse_attribute(priv_templ, CKA_IBM_DILITHIUM_SEED);
        cleanse_attribute(priv_templ, CKA_IBM_DILITHIUM_TR);
        cleanse_attribute(priv_templ, CKA_IBM_DILITHIUM_S1);
        cleanse_attribute(priv_templ, CKA_IBM_DILITHIUM_S2);
        cleanse_attribute(priv_templ, CKA_IBM_DILITHIUM_T0);
    }

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(priv_templ);

    return CKR_OK;
}

static CK_RV import_ibm_dilithium_pubkey(STDLL_TokData_t *tokdata,
                                         TEMPLATE *pub_templ)
{
    CK_RV rc;
    CK_ATTRIBUTE *opaque_attr = NULL;
    const struct pqc_oid *oid = NULL;
    CK_BYTE *spki = NULL;
    CK_ULONG spki_len = 0;

    rc = template_attribute_find(pub_templ, CKA_IBM_OPAQUE, &opaque_attr);
    if (rc == TRUE) {
        /*
         * This is an import of an existing secure QSA public key which
         * is stored in the CKA_IBM_OPAQUE attribute.
         */
        enum cca_token_type token_type;
        unsigned int token_keybitsize;
        const CK_BYTE *mkvp;
        uint8_t algo_id;
        uint16_t pubsec_len, algo_params, rho_len, t1_len;
        CK_BYTE *t;

        if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                                  &token_type, &token_keybitsize,
                                  &mkvp) != TRUE) {
            TRACE_ERROR("Invalid/unknown cca token in CKA_IBM_OPAQUE "
                        "attribute\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (token_type != sec_qsa_publ_key) {
            TRACE_ERROR("CCA token type in CKA_IBM_OPAQUE does not match to "
                        "keytype CKK_IBM_PQC_DILITHIUM\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* check dilithium variant and add keyform and mode attributes */
        t = opaque_attr->pValue;
        pubsec_len = be16toh(*((uint16_t *)(t + 2)));
        if (pubsec_len > (int)opaque_attr->ulValueLen) {
            TRACE_DEVEL("CCA QSA key token has invalid pub section len or "
                        "token size\n");
            return CKR_FUNCTION_FAILED;
        }

        algo_id = t[CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                CCA_QSA_EXTTOK_ALGO_ID_OFFSET];
        algo_params = be16toh(*((uint16_t *)(t + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                              CCA_QSA_EXTTOK_ALGO_PARAMS_OFFSET)));

        oid = get_pqc_oid_from_algo_info(algo_id, algo_params);
        if (oid == NULL) {
            TRACE_ERROR("Invalid/unknown algorithm ID in CCA QSA token\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (!cca_pqc_strength_supported(tokdata, CKM_IBM_DILITHIUM,
                                        oid->keyform)) {
            TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                        oid->keyform);
            return CKR_KEY_SIZE_RANGE;
        }

        rc = ibm_pqc_add_keyform_mode(pub_templ, oid, CKM_IBM_DILITHIUM);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
            return rc;
        }

        /* Extract RHO and T1 attributes */
        rho_len = be16toh(*((uint16_t *)(t + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                            CCA_QSA_EXTTOK_RHO_OFFSET)));
        t1_len = be16toh(*((uint16_t *)(t + CCA_QSA_EXTTOK_PUBLKEY_OFFSET+
                                            CCA_QSA_EXTTOK_T1_OFFSET)));

        rc = build_update_attribute(pub_templ, CKA_IBM_DILITHIUM_RHO,
                                    t + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                                CCA_QSA_EXTTOK_PAYLOAD_OFFSET,
                                    rho_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_update_attribute (RHO) failed\n");
            return rc;
        }

        rc = build_update_attribute(pub_templ, CKA_IBM_DILITHIUM_T1,
                                    t + CCA_QSA_EXTTOK_PUBLKEY_OFFSET +
                                                CCA_QSA_EXTTOK_PAYLOAD_OFFSET +
                                                rho_len,
                                    t1_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_update_attribute (T1) failed\n");
            return rc;
        }

        /* Add SPKI as CKA_VALUE to public template */
        rc = ibm_dilithium_publ_get_spki(pub_templ, FALSE, &spki, &spki_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_dilithium_publ_get_spki failed\n");
            return rc;
        }

        rc = build_update_attribute(pub_templ, CKA_VALUE, spki, spki_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_update_attribute for CKA_VALUE failed rv=0x%lx\n",
                        rc);
            free(spki);
            return rc;
        }

        free(spki);
    } else {
        /*
         * This is an import of a clear IBM dilithium public key which is to be
         * transferred into a CCA QSA public key.
         */

        long return_code, reason_code, rule_array_count, exit_data_len = 0;
        long private_key_name_length, key_token_length;
        unsigned char *exit_data = NULL;
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
        long key_value_structure_length;
        unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
        unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
        unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
        long param1 = 0;
        unsigned char *param2 = NULL;
        CK_ATTRIBUTE *attr = NULL;

        /* A clear IBM Dilithium key must either have a CKA_VALUE containing
         * the SPKI encoded public key, or must have a keyform/mode value
         * and the individual attributes
         */
        if (template_attribute_find(pub_templ, CKA_VALUE, &attr) == TRUE &&
            attr->ulValueLen > 0 && attr->pValue != NULL) {
            /* Public key in SPKI form is present in CKA_VALUE */
            rc = ibm_dilithium_priv_unwrap_get_data(pub_templ, attr->pValue,
                                                    attr->ulValueLen, FALSE);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to decode public key from CKA_VALUE.\n");
                return rc;
            }
        } else {
            /* Add SPKI as CKA_VALUE to public template */
            rc = ibm_dilithium_publ_get_spki(pub_templ, FALSE,
                                             &spki, &spki_len);
            if (rc != CKR_OK) {
                TRACE_ERROR("ibm_dilithium_publ_get_spki failed\n");
                return rc;
            }

            rc = build_update_attribute(pub_templ, CKA_VALUE, spki, spki_len);
            if (rc != CKR_OK) {
                TRACE_ERROR("build_update_attribute for CKA_VALUE failed "
                            "rv=0x%lx\n", rc);
                free(spki);
                return rc;
            }

            free(spki);
        }

        oid = ibm_pqc_get_keyform_mode(pub_templ, CKM_IBM_DILITHIUM);
        if (oid == NULL) {
            TRACE_ERROR("%s Failed to determine dilithium OID\n", __func__);
            return CKR_TEMPLATE_INCOMPLETE;
        }

        if (!cca_pqc_strength_supported(tokdata, CKM_IBM_DILITHIUM,
                                        oid->keyform)) {
            TRACE_DEVEL("Dilithium keyform %lu not supported by CCA\n",
                        oid->keyform);
            return CKR_KEY_SIZE_RANGE;
        }

        rc = ibm_pqc_add_keyform_mode(pub_templ, oid, CKM_IBM_DILITHIUM);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
            return rc;
        }

        /* Build key_value_structure */
        key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
        rc = build_ibm_dilithium_import_key_value_struct(
                                FALSE, oid, pub_templ,
                                (unsigned char *)&key_value_structure,
                                &key_value_structure_length);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_ibm_dilithium_import_key_value_struct failed: "
                        "0x%lx\n", rc);
            return rc;
        }

        /* Build key token */
        rule_array_count = 2;
        memcpy(rule_array, "QSA-PUBLU-DIGSIG", (size_t)(CCA_KEYWORD_SIZE * 2));
        private_key_name_length = 0;
        key_token_length = CCA_KEY_TOKEN_SIZE;

        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDPKB(&return_code, &reason_code,
                        &exit_data_len, exit_data,
                        &rule_array_count, rule_array,
                        &key_value_structure_length, key_value_structure,
                        &private_key_name_length, private_key_name,
                        &param1, param2, &param1, param2, &param1, param2,
                        &param1, param2, &param1, param2,
                        &key_token_length,
                        key_token);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNDPKB (QSA KEY TOKEN BUILD) failed. return:%ld,"
                        " reason:%ld\n", return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        /* Public keys do not need to be wrapped, so just add public
           key token to template as CKA_IBM_OPAQUE */
        if ((rc = build_update_attribute(pub_templ, CKA_IBM_OPAQUE,
                                         key_token, key_token_length))) {
            TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
            return rc;
        }
    }

    TRACE_DEBUG("%s: imported object template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(pub_templ);

    return CKR_OK;
}

CK_RV token_specific_object_add(STDLL_TokData_t *tokdata, SESSION *sess, OBJECT *object)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CK_OBJECT_CLASS keyclass;

    UNUSED(sess);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    if (!object) {
        TRACE_ERROR("Invalid argument\n");
        return CKR_FUNCTION_FAILED;
    }

    /* we only deal with key objects here */
    rc = template_attribute_get_ulong(object->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        // not a key, so nothing to do. Just return.
        TRACE_DEVEL("object not a key, no need to import.\n");
        return CKR_OK;
    }

    /* CKA_CLASS is mandatory */
    rc = template_attribute_get_ulong(object->template, CKA_CLASS, &keyclass);
    if (rc != CKR_OK) {
        TRACE_ERROR("object has no CKA_CLASS value %s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    switch (keytype) {
    case CKK_RSA:
        switch (keyclass) {
        case CKO_PUBLIC_KEY:
            // do import public key and create opaque object
            rc = import_rsa_pubkey(tokdata, object->template);
            if (rc != CKR_OK) {
                TRACE_DEVEL("RSA public key import failed, rc=0x%lx\n", rc);
                return rc;
            }
            TRACE_INFO("RSA public key imported\n");
            break;
        case CKO_PRIVATE_KEY:
            // do import keypair and create opaque object
            rc = import_rsa_privkey(tokdata, object->template);
            if (rc != CKR_OK) {
                TRACE_DEVEL("RSA private key import failed, rc=0x%lx\n", rc);
                return rc;
            }
            TRACE_INFO("RSA private key imported\n");
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;

#ifndef NO_PKEY
    case CKK_AES_XTS:
        rc = import_aes_xts_key(tokdata, object);
        if (rc != CKR_OK) {
            TRACE_DEVEL("AES XTS key import failed, rc=0x%lx\n", rc);
            return rc;
        }

        template_attribute_find(object->template, CKA_VALUE, &attr);
        TRACE_INFO("AES XTS key with len=%ld successfully imported\n",
                   attr != NULL ? attr->ulValueLen : 0);
        break;
#endif

    case CKK_AES:
    case CKK_DES:
    case CKK_DES3:
        rc = import_symmetric_key(tokdata, object, keytype);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Symmetric key import failed, rc=0x%lx\n", rc);
            return rc;
        }
        template_attribute_find(object->template, CKA_VALUE, &attr);
        TRACE_INFO("symmetric key with len=%ld successful imported\n",
                   attr != NULL ? attr->ulValueLen : 0);
        break;
    case CKK_GENERIC_SECRET:
        rc = import_generic_secret_key(tokdata, object);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Generic Secret (HMAC) key import failed "
                        " with rc=0x%lx\n", rc);
            return rc;
        }
        template_attribute_find(object->template, CKA_VALUE, &attr);
        TRACE_INFO("Generic Secret (HMAC) key with len=%ld successfully"
                   " imported\n", attr != NULL ? attr->ulValueLen : 0);
        break;
    case CKK_EC:
        switch (keyclass) {
        case CKO_PUBLIC_KEY:
            // do import public key and create opaque object
            rc = import_ec_pubkey(tokdata, object->template);
            if (rc != CKR_OK) {
                TRACE_DEVEL("ECpublic key import failed, rc=0x%lx\n", rc);
                return rc;
            }
            TRACE_INFO("EC public key imported\n");
            break;
        case CKO_PRIVATE_KEY:
            // do import keypair and create opaque object
            rc = import_ec_privkey(tokdata, object->template);
            if (rc != CKR_OK) {
                TRACE_DEVEL("EC private key import failed, rc=0x%lx\n", rc);
                return rc;
            }
            TRACE_INFO("EC private key imported\n");
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;
    case CKK_IBM_PQC_DILITHIUM:
        switch (keyclass) {
        case CKO_PUBLIC_KEY:
            // do import public key and create opaque object
            rc = import_ibm_dilithium_pubkey(tokdata, object->template);
            if (rc != CKR_OK) {
                TRACE_DEVEL("Dilithium public key import failed, rc=0x%lx\n",
                            rc);
                return rc;
            }
            TRACE_INFO("Dilithium public key imported\n");
            break;
        case CKO_PRIVATE_KEY:
            // do import keypair and create opaque object
            rc = import_ibm_dilithium_privkey(tokdata, object->template);
            if (rc != CKR_OK) {
                TRACE_DEVEL("Dilithium private key import failed, rc=0x%lx\n",
                            rc);
                return rc;
            }
            TRACE_INFO("Dilithium private key imported\n");
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;
    default:
        /* unknown/unsupported key type */
        TRACE_ERROR("Unknown/unsupported key type 0x%lx\n", keytype);
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    return CKR_OK;
}

CK_RV token_specific_generic_secret_key_gen(STDLL_TokData_t * tokdata,
                                            TEMPLATE * template)
{
    CK_RV rc;
    long return_code, reason_code, rule_array_count;
    long zero_length = 0;
    long key_name_length = 0, clear_key_length = 0, user_data_length = 0;
    CK_ATTRIBUTE *opaque_key = NULL;
    CK_ULONG keylength = 0;
    unsigned char key_type1[8] = { 0 };
    unsigned char key_type2[8] = { 0 };
    unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0 };
    long key_token_length = sizeof(key_token);
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk, extractable = TRUE;

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = template_attribute_get_ulong(template, CKA_VALUE_LEN, &keylength);
    if (rc != CKR_OK) {
        TRACE_ERROR("CKA_VALUE_LEN missing in (HMAC) key template\n");
        return rc;
    }

    /* HMAC key length needs to be 80-2048 bits */
    if ((keylength < (80 / 8)) || (keylength > (2048 / 8))) {
        TRACE_ERROR("HMAC key size of %lu bits not within CCA required "
                    "range of 80-2048 bits\n", 8 * keylength);
        return CKR_KEY_SIZE_RANGE;
    }

    rule_array_count = 4;
    memcpy(rule_array, "INTERNALHMAC    MAC     GENERATE",
           4 * CCA_KEYWORD_SIZE);

    rc = template_attribute_get_bool(template, CKA_EXTRACTABLE,
                                     &extractable);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE) {
        TRACE_ERROR("Failed to get CKA_EXTRACTABLE\n");
        return rc;
    }

    if (!extractable) {
        memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
               "NOEX-SYMNOEXUASYNOEXAASYNOEX-DESNOEX-AESNOEX-RSA",
               6 * CCA_KEYWORD_SIZE);
        rule_array_count += 6;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                     rule_array, &clear_key_length, NULL, &key_name_length,
                     NULL, &user_data_length, NULL, &zero_length, NULL,
                     &zero_length, NULL, &key_token_length, key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBKTB2 (HMAC KEY TOKEN BUILD) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

        /** generate the hmac key here **/
    /* reset some values usually previously */
    rule_array_count = 2;
    memset(rule_array, 0, sizeof(rule_array));

    key_token_length = sizeof(key_token);

    /* create rule_array with 2 keywords */
    memcpy(rule_array, "HMAC    OP      ", 2 * CCA_KEYWORD_SIZE);

    /* ask to create the hmac key with application
     * specified key length in bits
     */
    clear_key_length = keylength * 8;
    memcpy(key_type1, "TOKEN   ", CCA_KEYWORD_SIZE);

    /* for only one copy of key generated, specify 8 spaces in
     * key_type2 per CCA basic services guide
     */
    memcpy(key_type2, "        ", CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBKGN2(&return_code, &reason_code, &zero_length, NULL,
                     &rule_array_count, rule_array,
                     &clear_key_length, key_type1,
                     key_type2, &key_name_length, NULL, &key_name_length, NULL,
                     &user_data_length, NULL, &user_data_length, NULL,
                     &zero_length, NULL, &zero_length, NULL,
                     &key_token_length, key_token,
                     &zero_length, NULL);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBKGN2 (HMAC KEY GENERATE) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(key_token, key_token_length,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been generated\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = cca_reencipher_created_key(tokdata, template, key_token,
                                    key_token_length, new_mk, keytype, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        return rc;
    }

    /* Add the key object to the template */
    rc = build_attribute(CKA_IBM_OPAQUE, key_token, key_token_length,
                         &opaque_key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_IBM_OPAQUE) failed\n");
        return rc;
    }

    rc = template_update_attribute(template, opaque_key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute(CKA_IBM_OPAQUE) failed.\n");
        free(opaque_key);
        return rc;
    }

    TRACE_DEBUG("%s: secret key template attributes:\n", __func__);
    TRACE_DEBUG_DUMPTEMPL(template);

    return CKR_OK;
}

static CK_RV ccatok_wrap_key_rsa_pkcs(STDLL_TokData_t *tokdata,
                                      CK_MECHANISM *mech, CK_BBOOL length_only,
                                      OBJECT *wrapping_key, OBJECT *key,
                                      CK_BYTE *wrapped_key,
                                      CK_ULONG *wrapped_key_len)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
    CK_BYTE buffer[900] = { 0, };
    long buffer_len = sizeof(buffer);
    CK_ATTRIBUTE *key_opaque, *wrap_key_opaque;
    CK_OBJECT_CLASS key_class;
    CK_KEY_TYPE key_type;
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_RV rc;

    rc = template_attribute_get_ulong(key->template, CKA_CLASS, &key_class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    if (key_class != CKO_SECRET_KEY)
        return CKR_KEY_NOT_WRAPPABLE;

    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE,
                                          &key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    if (analyse_cca_key_token((CK_BYTE *)key_opaque->pValue,
                              key_opaque->ulValueLen,
                              &keytype, &keybitsize, &mkvp) == FALSE) {
        TRACE_ERROR("Invalid/unknown cca token, cannot get key type\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &key_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        return rc;
    }

    switch (key_type) {
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
        switch (mech->mechanism) {
        case CKM_RSA_PKCS:
            rule_array_count = 2;
            memcpy(rule_array, "DES     PKCS-1.2", 2 * CCA_KEYWORD_SIZE);
            break;
        case CKM_RSA_PKCS_OAEP:
            rule_array_count = 3;
            oaep = (CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter;
            if (oaep == NULL ||
                mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            if (oaep->source == CKZ_DATA_SPECIFIED &&
                oaep->ulSourceDataLen > 0) {
                TRACE_ERROR("CCA doesn't support non-empty OAEP source data\n");
                return CKR_MECHANISM_PARAM_INVALID;
            }

            switch (oaep->hashAlg) {
            case CKM_SHA_1:
                if (oaep->mgf != CKG_MGF1_SHA1)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "DES     PKCSOAEPSHA-1   ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            case CKM_SHA256:
                if (oaep->mgf != CKG_MGF1_SHA256)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "DES     PKCSOAEPSHA-256 ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            default:
                return CKR_MECHANISM_PARAM_INVALID;
            }
            break;
        default:
            return CKR_MECHANISM_INVALID;
        }
        break;
    case CKK_AES:
        switch (mech->mechanism) {
        case CKM_RSA_PKCS:
            if (keytype == sec_aes_cipher_key) {
                TRACE_ERROR("CCA does not support wrapping with CKM_RSA_PKCS "
                            "for AES CIPHER keys\n");
                return CKR_KEY_NOT_WRAPPABLE;
            }

            rule_array_count = 2;
            memcpy(rule_array, "AES     PKCS-1.2", 2 * CCA_KEYWORD_SIZE);
            break;
        case CKM_RSA_PKCS_OAEP:
            if (keytype == sec_aes_cipher_key) {
                TRACE_ERROR("CCA does not support wrapping with "
                            "CKM_RSA_PKCS_OAEP for AES CIPHER keys\n");
                return CKR_KEY_NOT_WRAPPABLE;
            }

            rule_array_count = 3;
            oaep = (CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter;
            if (oaep == NULL ||
                mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            if (oaep->source == CKZ_DATA_SPECIFIED &&
                oaep->ulSourceDataLen > 0) {
                TRACE_ERROR("CCA does not support non-empty OAEP source "
                            "data\n");
                return CKR_MECHANISM_PARAM_INVALID;
            }

            switch (oaep->hashAlg) {
            case CKM_SHA_1:
                if (oaep->mgf != CKG_MGF1_SHA1)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "AES     PKCSOAEPSHA-1   ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            case CKM_SHA256:
                if (oaep->mgf != CKG_MGF1_SHA256)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "AES     PKCSOAEPSHA-256 ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            default:
                return CKR_MECHANISM_PARAM_INVALID;
            }
            break;
        default:
            return CKR_MECHANISM_INVALID;
        }
        break;
    default:
        return CKR_KEY_NOT_WRAPPABLE;
    }

    rc = template_attribute_get_non_empty(wrapping_key->template,
                                          CKA_IBM_OPAQUE, &wrap_key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the wrapping key.\n");
        return rc;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDSYX(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                    rule_array, (long *)&key_opaque->ulValueLen,
                    key_opaque->pValue, (long *)&wrap_key_opaque->ulValueLen,
                    wrap_key_opaque->pValue, &buffer_len, buffer);
    RETRY_NEW_MK_BLOB2_END(tokdata, return_code, reason_code,
                           key_opaque->pValue, key_opaque->ulValueLen,
                           wrap_key_opaque->pValue, wrap_key_opaque->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDSYX (SYMMETRIC KEY EXPORT) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (length_only) {
        *wrapped_key_len = buffer_len;
        return CKR_OK;
    }

    if ((CK_ULONG)buffer_len > *wrapped_key_len) {
        *wrapped_key_len = buffer_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(wrapped_key, buffer, buffer_len);
    *wrapped_key_len = buffer_len;

    return CKR_OK;
}

static CK_RV ccatok_unwrap_key_rsa_pkcs(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM *mech,
                                        OBJECT *wrapping_key, OBJECT *key,
                                        CK_BYTE *wrapped_key,
                                        CK_ULONG wrapped_key_len)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
    CK_BYTE buffer[3500] = { 0, };
    CK_BYTE dummy[AES_KEY_SIZE_256] = { 0, };
    long buffer_len = sizeof(buffer);
    CK_ATTRIBUTE *wrap_key_opaque,*key_opaque = NULL;
    CK_ATTRIBUTE *value = NULL, *value_len = NULL;
    CK_OBJECT_CLASS key_class;
    CK_KEY_TYPE key_type, cca_key_type;
    CK_ULONG key_size = 0;
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;
    uint16_t val;
    CK_IBM_CCA_AES_KEY_MODE_TYPE mode;
    CK_RV rc;

    rc = template_attribute_get_ulong(key->template, CKA_CLASS, &key_class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    if (key_class != CKO_SECRET_KEY)
        return CKR_WRAPPED_KEY_INVALID;

    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &key_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        return rc;
    }

    switch (key_type) {
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
        switch (mech->mechanism) {
        case CKM_RSA_PKCS:
            rule_array_count = 2;
            memcpy(rule_array, "DES     PKCS-1.2", 2 * CCA_KEYWORD_SIZE);
            break;
        case CKM_RSA_PKCS_OAEP:
            rule_array_count = 3;
            oaep = (CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter;
            if (oaep == NULL ||
                mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            if (oaep->source == CKZ_DATA_SPECIFIED &&
                oaep->ulSourceDataLen > 0) {
                TRACE_ERROR("CCA does not support non-empty OAEP source "
                            "data\n");
                return CKR_MECHANISM_PARAM_INVALID;
            }

            switch (oaep->hashAlg) {
            case CKM_SHA_1:
                if (oaep->mgf != CKG_MGF1_SHA1)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "DES     PKCSOAEPSHA-1   ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            case CKM_SHA256:
                if (oaep->mgf != CKG_MGF1_SHA256)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "DES     PKCSOAEPSHA-256 ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            default:
                return CKR_MECHANISM_PARAM_INVALID;
            }
            break;
        default:
            return CKR_MECHANISM_INVALID;
        }
        break;
    case CKK_AES:
        rc = cca_get_and_set_aes_key_mode(tokdata, key->template, &mode);
        if (rc != CKR_OK) {
            TRACE_DEVEL("cca_get_and_set_aes_key_mode failed\n");
            return rc;
        }

        switch (mech->mechanism) {
        case CKM_RSA_PKCS:
            if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
                TRACE_ERROR("CCA does not support to unwrap with CKM_RSA_PKCS "
                            "for AES CIPHER keys\n");
                return CKR_WRAPPED_KEY_INVALID;
            }

            rule_array_count = 2;
            memcpy(rule_array, "AES     PKCS-1.2", 2 * CCA_KEYWORD_SIZE);
            break;
        case CKM_RSA_PKCS_OAEP:
            if (mode == CK_IBM_CCA_AES_CIPHER_KEY) {
                TRACE_ERROR("CCA does not support to unwrap with "
                            "CKM_RSA_PKCS_OAEP for AES CIPHER keys\n");
                return CKR_WRAPPED_KEY_INVALID;
            }

            rule_array_count = 3;
            oaep = (CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter;
            if (oaep == NULL ||
                mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            if (oaep->source == CKZ_DATA_SPECIFIED &&
                oaep->ulSourceDataLen > 0) {
                TRACE_ERROR("CCA does not support non-empty OAEP source "
                            "data\n");
                return CKR_MECHANISM_PARAM_INVALID;
            }

            switch (oaep->hashAlg) {
            case CKM_SHA_1:
                if (oaep->mgf != CKG_MGF1_SHA1)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "AES     PKCSOAEPSHA-1   ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            case CKM_SHA256:
                if (oaep->mgf != CKG_MGF1_SHA256)
                    return CKR_MECHANISM_PARAM_INVALID;
                memcpy(rule_array, "AES     PKCSOAEPSHA-256 ",
                       3 * CCA_KEYWORD_SIZE);
                break;
            default:
                return CKR_MECHANISM_PARAM_INVALID;
            }
            break;
        default:
            return CKR_MECHANISM_INVALID;
        }
        break;
    default:
        return CKR_WRAPPED_KEY_INVALID;
    }

    rc = template_attribute_get_non_empty(wrapping_key->template,
                                          CKA_IBM_OPAQUE, &wrap_key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the wrapping key.\n");
        return rc;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDSYI(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                    rule_array, (long *)&wrapped_key_len, wrapped_key,
                    (long *)&wrap_key_opaque->ulValueLen, wrap_key_opaque->pValue,
                    &buffer_len, buffer);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          wrap_key_opaque->pValue, wrap_key_opaque->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDSYI (SYMMETRIC KEY IMPORT) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (buffer[0] != 0x01) { /* Internal key token */
        TRACE_DEVEL("key token invalid\n");
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(buffer, buffer_len,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been unwrapped\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = cca_reencipher_created_key(tokdata, key->template, buffer, buffer_len,
                                    new_mk, keytype, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        return rc;
    }

    switch (buffer[4]) {
    case 0x00: /* DES key token */
    case 0x01: { /* DES3 key token */
        /* analyse_cca_key_token has already reliably identified
           the token type, so use that */
        switch(keybitsize) {
        case (1 * DES_KEY_SIZE * 8):
            cca_key_type = CKK_DES;
            key_size = DES_KEY_SIZE;
            break;

        case (2 * DES_KEY_SIZE * 8):
            cca_key_type = CKK_DES2;
            key_size = 2 * DES_KEY_SIZE;
            break;

        case (3 * DES_KEY_SIZE * 8):
            cca_key_type = CKK_DES3;
            key_size = 3 * DES_KEY_SIZE;
            break;

        default:
            TRACE_DEVEL("key token invalid\n");
            return CKR_FUNCTION_FAILED;
        }
        break;
    }
    case 0x04:/* AES key token */
        cca_key_type = CKK_AES;
        memcpy(&val, &buffer[56], sizeof(val));
        key_size = be16toh(val) / 8;
        break;
    default:
        TRACE_DEVEL("key token invalid\n");
        return CKR_FUNCTION_FAILED;
    }

    if (key_type != cca_key_type) {
        TRACE_DEVEL("Wrong key type\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, buffer, buffer_len, &key_opaque);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }

    rc = build_attribute(CKA_VALUE, dummy, key_size, &value);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    switch (key_type) {
    case CKK_GENERIC_SECRET:
    case CKK_AES:
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *)&key_size,
                             sizeof(CK_ULONG), &value_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto error;
        }
        break;
    default:
        break;
    }

    rc = template_update_attribute(key->template, key_opaque);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    key_opaque = NULL;
    rc = template_update_attribute(key->template, value);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    value = NULL;
    if (value_len != NULL) {
        rc = template_update_attribute(key->template, value_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed\n");
            goto error;
        }
        value_len = NULL;
    }

    return CKR_OK;

error:
    if (key_opaque)
        free(key_opaque);
    if (value)
        free(value);
    if (value_len)
        free(value_len);

    return rc;
}

static CK_RV ccatok_wrap_key_rsa_aeskw_aes(STDLL_TokData_t *tokdata,
                                           CK_BBOOL length_only,
                                           CK_ATTRIBUTE *wrap_key_opaque,
                                           CK_ATTRIBUTE *key_opaque,
                                           CK_BYTE *wrapped_key,
                                           CK_ULONG *wrapped_key_len)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
    CK_BYTE buffer[3500] = { 0, };
    long buffer_len = sizeof(buffer);
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;

    if (!cca_rsa_aeskw_supported(tokdata, CKK_AES)) {
        TRACE_ERROR("CKM_RSA_AES_KEY_WRAP requires CCA 8.2 or later and "
                    "certain ACPs set for wrapping AES keys\n");
        return CKR_KEY_NOT_WRAPPABLE;
    }

    if (analyse_cca_key_token((CK_BYTE *)key_opaque->pValue,
                              key_opaque->ulValueLen,
                              &keytype, &keybitsize, &mkvp) == FALSE) {
        TRACE_ERROR("Invalid/unknown cca token, cannot get key type\n");
        return CKR_FUNCTION_FAILED;
    }

    if (keytype != sec_aes_cipher_key) {
        TRACE_ERROR("CCA does not support wrapping with CKM_RSA_AES_KEY_WRAP "
                    "for AES DATA keys\n");
        return CKR_KEY_NOT_WRAPPABLE;
    }

    rule_array_count = 2;
    memcpy(rule_array, "AES     CKM-RAKW", 2 * CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDSYX(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                    rule_array, (long *)&key_opaque->ulValueLen,
                    key_opaque->pValue, (long *)&wrap_key_opaque->ulValueLen,
                    wrap_key_opaque->pValue, &buffer_len, buffer);
    RETRY_NEW_MK_BLOB2_END(tokdata, return_code, reason_code,
                           key_opaque->pValue, key_opaque->ulValueLen,
                           wrap_key_opaque->pValue, wrap_key_opaque->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDSYX (SYMMETRIC KEY EXPORT) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);

        if (return_code == 8 && reason_code == 90)
            return CKR_FUNCTION_CANCELED; /* Control point prohibits function */
        if (return_code == 8 && reason_code == 760)
            return CKR_WRAPPING_KEY_SIZE_RANGE; /* must be  >= 2048 bit */
        return CKR_FUNCTION_FAILED;
    }

    if (length_only) {
        *wrapped_key_len = buffer_len;
        return CKR_OK;
    }

    if ((CK_ULONG)buffer_len > *wrapped_key_len) {
        *wrapped_key_len = buffer_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(wrapped_key, buffer, buffer_len);
    *wrapped_key_len = buffer_len;

    return CKR_OK;
}

static CK_RV ccatok_wrap_key_rsa_aeskw(STDLL_TokData_t *tokdata,
                                       CK_MECHANISM *mech,
                                       CK_BBOOL length_only,
                                       OBJECT *wrapping_key, OBJECT *key,
                                       CK_BYTE *wrapped_key,
                                       CK_ULONG *wrapped_key_len)
{
    CK_ATTRIBUTE *key_opaque, *wrap_key_opaque;
    CK_OBJECT_CLASS key_class;
    CK_KEY_TYPE key_type;
    CK_RSA_AES_KEY_WRAP_PARAMS *params;
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    CK_RV rc;

    params = (CK_RSA_AES_KEY_WRAP_PARAMS *)mech->pParameter;
    if (params == NULL ||
        mech->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS))
        return CKR_MECHANISM_PARAM_INVALID;

    if (params->ulAESKeyBits != 256) {
        TRACE_ERROR("CCA only supports AES-256 as temporary key size\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    oaep = params->pOAEPParams;
    if (oaep == NULL)
        return CKR_MECHANISM_PARAM_INVALID;

    if (oaep->source == CKZ_DATA_SPECIFIED &&
        oaep->ulSourceDataLen > 0) {
        TRACE_ERROR("CCA does not support non-empty OAEP source data\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (oaep->hashAlg != CKM_SHA_1 || oaep->mgf != CKG_MGF1_SHA1) {
        TRACE_ERROR("CCA only supports SHA-1 as hash algorithm and MGF\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    rc = template_attribute_get_non_empty(wrapping_key->template,
                                          CKA_IBM_OPAQUE, &wrap_key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the wrapping key.\n");
        return rc;
    }

    rc = template_attribute_get_ulong(key->template, CKA_CLASS, &key_class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &key_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_IBM_OPAQUE,
                                          &key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
        return rc;
    }

    switch (key_class) {
    case CKO_SECRET_KEY:
        switch (key_type) {
        case CKK_AES:
            return ccatok_wrap_key_rsa_aeskw_aes(tokdata, length_only,
                                                 wrap_key_opaque, key_opaque,
                                                 wrapped_key, wrapped_key_len);
        default:
            TRACE_ERROR("The type of they key to wrap is not supported.\n");
            return CKR_KEY_NOT_WRAPPABLE;
        }
        break;
    default:
        TRACE_ERROR("The class of the key to wrap is not supported.\n");
        return CKR_KEY_NOT_WRAPPABLE;
    }
}

static CK_RV ccatok_unwrap_key_rsa_aeskw_aes(STDLL_TokData_t *tokdata,
                                             CK_ATTRIBUTE *wrap_key_opaque,
                                             OBJECT *key,
                                             CK_BYTE *wrapped_key,
                                             CK_ULONG wrapped_key_len)
{
    long return_code, reason_code, rule_array_count;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
    unsigned char exit_data[4] = { 0, };
    unsigned char key_name[CCA_KEY_ID_SIZE] = { 0, };
    long exit_data_len = 0, key_name_length = 0;
    CK_BYTE buffer[725] = { 0, };
    CK_BYTE dummy[AES_KEY_SIZE_256] = { 0, };
    long buffer_len = sizeof(buffer);
    CK_ULONG buf_len = sizeof(buffer);
    CK_ATTRIBUTE *key_opaque = NULL;
    CK_ATTRIBUTE *value = NULL, *value_len = NULL;
    CK_ULONG key_size = 0;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_BBOOL new_mk;
    CK_IBM_CCA_AES_KEY_MODE_TYPE mode;
    CK_RV rc;

    if (!cca_rsa_aeskw_supported(tokdata, CKK_AES)) {
        TRACE_ERROR("CKM_RSA_AES_KEY_WRAP requires CCA 8.2 or later and "
                    "certain ACPs set for unwrapping AES keys\n");
        return CKR_WRAPPED_KEY_INVALID;
    }

    rc = cca_get_and_set_aes_key_mode(tokdata, key->template, &mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("cca_get_and_set_aes_key_mode failed\n");
        return rc;
    }

    if (mode != CK_IBM_CCA_AES_CIPHER_KEY) {
        TRACE_ERROR("CCA does not support unwrapping with CKM_RSA_AES_KEY_WRAP "
                    "for AES DATA keys\n");
        return CKR_WRAPPED_KEY_INVALID;
    }

    rc = cca_build_aes_cipher_token(tokdata, key->template,
                                    buffer, &buf_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("cca_build_aes_cipher_token failed\n");
        return rc;
    }

    rule_array_count = 2;
    memcpy(rule_array, "AES     CKM-RAKW", 2 * CCA_KEYWORD_SIZE);

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNDSYI2(&return_code, &reason_code,
                     &exit_data_len, exit_data,
                     &rule_array_count, rule_array,
                     (long *)&wrapped_key_len, wrapped_key,
                     (long *)&wrap_key_opaque->ulValueLen,
                     wrap_key_opaque->pValue,
                     &key_name_length, key_name,
                     &buffer_len, buffer);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          wrap_key_opaque->pValue, wrap_key_opaque->ulValueLen)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNDSYI2 (SYMMETRIC KEY IMPORT2) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);

        if (return_code == 8 && reason_code == 90)
            return CKR_FUNCTION_CANCELED; /* Control point prohibits function */
        if (return_code == 8 && reason_code == 33)
            return CKR_FUNCTION_CANCELED; /* Control point prohibits function */
        if (return_code == 8 && reason_code == 760)
            return CKR_UNWRAPPING_KEY_SIZE_RANGE; /* must be  >= 2048 bit */
        if (return_code == 8 && reason_code == 55)
            return CKR_WRAPPED_KEY_INVALID; /* temp AES key not 256 bits */
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(buffer, buffer_len,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been unwrapped\n");
        return CKR_FUNCTION_FAILED;
    }

    if (keytype != sec_aes_cipher_key) {
        TRACE_ERROR("Invalid cca token has been unwrapped\n");
        return CKR_FUNCTION_FAILED;
    }

    if (keybitsize == 0) {
        /* Indicates V1 payload. Get unwrapped key size from wrapped data */
        if (analyse_cca_key_token(wrap_key_opaque->pValue,
                                  wrap_key_opaque->ulValueLen,
                                  &keytype, &keybitsize, &mkvp) == FALSE ||
            mkvp == NULL) {
            TRACE_ERROR("Invalid/unknown cca token used as wrapping key\n");
            return CKR_FUNCTION_FAILED;
        }

        /* Unwrapped key size is input size - RSA modulus size - AESKW block */
        key_size = wrapped_key_len - (keybitsize / 8) - AES_KEY_WRAP_BLOCK_SIZE;
    } else {
        key_size = keybitsize / 8;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = cca_reencipher_created_key(tokdata, key->template, buffer, buffer_len,
                                    new_mk, keytype, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        return rc;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, buffer, buffer_len, &key_opaque);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }

    rc = build_attribute(CKA_VALUE, dummy, key_size, &value);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }

    rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *)&key_size,
                         sizeof(CK_ULONG), &value_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }

    rc = template_update_attribute(key->template, key_opaque);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    key_opaque = NULL;
    rc = template_update_attribute(key->template, value);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    value = NULL;
    if (value_len != NULL) {
        rc = template_update_attribute(key->template, value_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed\n");
            goto error;
        }
        value_len = NULL;
    }

    return CKR_OK;

error:
    if (key_opaque)
        free(key_opaque);
    if (value)
        free(value);
    if (value_len)
        free(value_len);

    return rc;
}

static CK_RV ccatok_unwrap_key_rsa_aeskw(STDLL_TokData_t *tokdata,
                                         CK_MECHANISM *mech,
                                         OBJECT *wrapping_key, OBJECT *key,
                                         CK_BYTE *wrapped_key,
                                         CK_ULONG wrapped_key_len)
{
    CK_ATTRIBUTE *wrap_key_opaque;
    CK_OBJECT_CLASS key_class;
    CK_KEY_TYPE key_type;
    CK_RSA_AES_KEY_WRAP_PARAMS *params;
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    CK_RV rc;

    params = (CK_RSA_AES_KEY_WRAP_PARAMS *)mech->pParameter;
    if (params == NULL ||
        mech->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS))
        return CKR_MECHANISM_PARAM_INVALID;

    /* CCA always uses a AES-256 bit temporary key */
    if (params->ulAESKeyBits == 0)
        params->ulAESKeyBits = 256;
    if (params->ulAESKeyBits != 256) {
        TRACE_ERROR("CCA only supports AES-256 as temporary key size\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    oaep = params->pOAEPParams;
    if (oaep == NULL)
        return CKR_MECHANISM_PARAM_INVALID;

    if (oaep->source == CKZ_DATA_SPECIFIED &&
        oaep->ulSourceDataLen > 0) {
        TRACE_ERROR("CCA does not support non-empty OAEP source data\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (oaep->hashAlg != CKM_SHA_1 || oaep->mgf != CKG_MGF1_SHA1) {
        TRACE_ERROR("CCA only supports SHA-1 as hash algorithm and MGF\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    rc = template_attribute_get_non_empty(wrapping_key->template,
                                          CKA_IBM_OPAQUE, &wrap_key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the wrapping key.\n");
        return rc;
    }

    rc = template_attribute_get_ulong(key->template, CKA_CLASS, &key_class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &key_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        return rc;
    }

    switch (key_class) {
    case CKO_SECRET_KEY:
        switch (key_type) {
        case CKK_AES:
            return ccatok_unwrap_key_rsa_aeskw_aes(tokdata, wrap_key_opaque,
                                                   key, wrapped_key,
                                                   wrapped_key_len);
        default:
            TRACE_ERROR("The type of they key to wrap is not supported.\n");
            return CKR_KEY_NOT_WRAPPABLE;
        }
        break;
    default:
        TRACE_ERROR("The class of the key to wrap is not supported.\n");
        return CKR_KEY_NOT_WRAPPABLE;
    }
    return CKR_OK;
}

CK_RV token_specific_key_wrap(STDLL_TokData_t *tokdata, SESSION *session,
                              CK_MECHANISM *mech, CK_BBOOL length_only,
                              OBJECT *wrapping_key, OBJECT *key,
                              CK_BYTE *wrapped_key, CK_ULONG *wrapped_key_len,
                              CK_BBOOL *not_opaque)
{
    CK_OBJECT_CLASS wrap_key_class;
    CK_KEY_TYPE wrap_key_type;
    CK_RV rc;

    UNUSED(session);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    *not_opaque = FALSE;

    rc = template_attribute_get_ulong(wrapping_key->template, CKA_CLASS,
                                      &wrap_key_class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the wrapping key.\n");
        return rc;
    }

    rc = template_attribute_get_ulong(wrapping_key->template, CKA_KEY_TYPE,
                                      &wrap_key_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the wrapping key.\n");
        return rc;
    }

    switch (mech->mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
        if (wrap_key_class != CKO_PUBLIC_KEY && wrap_key_type != CKK_RSA)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

        return ccatok_wrap_key_rsa_pkcs(tokdata,
                                        mech, length_only, wrapping_key, key,
                                        wrapped_key, wrapped_key_len);
    case CKM_RSA_AES_KEY_WRAP:
        if (wrap_key_class != CKO_PUBLIC_KEY && wrap_key_type != CKK_RSA)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

        return ccatok_wrap_key_rsa_aeskw(tokdata,
                                         mech, length_only, wrapping_key, key,
                                         wrapped_key, wrapped_key_len);
    default:
        return CKR_MECHANISM_INVALID;
    }
 }

CK_RV token_specific_key_unwrap(STDLL_TokData_t *tokdata, SESSION *session,
                                CK_MECHANISM *mech,
                                CK_BYTE *wrapped_key, CK_ULONG wrapped_key_len,
                                OBJECT *unwrapping_key, OBJECT *unwrapped_key,
                                CK_BBOOL *not_opaque)
{
    CK_ATTRIBUTE *local = NULL, *always_sens = NULL, *sensitive = NULL;
    CK_ATTRIBUTE *extractable = NULL, *never_extract = NULL;
    CK_OBJECT_CLASS unwrap_key_class;
    CK_KEY_TYPE unwrap_keytype;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_RV rc;

    UNUSED(session);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    *not_opaque = FALSE;

    rc = template_attribute_get_ulong(unwrapping_key->template, CKA_CLASS,
                                      &unwrap_key_class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    rc = template_attribute_get_ulong(unwrapping_key->template, CKA_KEY_TYPE,
                                      &unwrap_keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        return rc;
    }


    switch (mech->mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
        if (unwrap_key_class != CKO_PRIVATE_KEY && unwrap_keytype != CKK_RSA)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

        rc = ccatok_unwrap_key_rsa_pkcs(tokdata,
                                        mech, unwrapping_key, unwrapped_key,
                                        wrapped_key, wrapped_key_len);
        if (rc != CKR_OK)
            goto error;
        break;
    case CKM_RSA_AES_KEY_WRAP:
        if (unwrap_key_class != CKO_PRIVATE_KEY && unwrap_keytype != CKK_RSA)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

        rc = ccatok_unwrap_key_rsa_aeskw(tokdata,
                                         mech, unwrapping_key, unwrapped_key,
                                         wrapped_key, wrapped_key_len);
        if (rc != CKR_OK)
            goto error;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    /*
     * make sure
     *   CKA_LOCAL             == FALSE
     *    CKA_ALWAYS_SENSITIVE  == FALSE
     *    CKA_EXTRACTABLE       == TRUE
     *    CKA_NEVER_EXTRACTABLE == FALSE
     */
    rc = build_attribute(CKA_LOCAL, &false, 1, &local);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed\n");
        goto error;
    }
    rc = build_attribute(CKA_ALWAYS_SENSITIVE, &false, 1, &always_sens);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed\n");
        goto error;
    }
    rc = build_attribute(CKA_SENSITIVE, &false, 1, &sensitive);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = build_attribute(CKA_EXTRACTABLE, &true, 1, &extractable);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = build_attribute(CKA_NEVER_EXTRACTABLE, &false, 1, &never_extract);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }

    rc = template_update_attribute(unwrapped_key->template, local);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    local = NULL;
    rc = template_update_attribute(unwrapped_key->template, always_sens);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    always_sens = NULL;
    rc = template_update_attribute(unwrapped_key->template, sensitive);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    sensitive = NULL;
    rc = template_update_attribute(unwrapped_key->template, extractable);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    extractable = NULL;
    rc = template_update_attribute(unwrapped_key->template, never_extract);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    never_extract = NULL;

    return CKR_OK;

error:
    if (local)
        free(local);
    if (extractable)
        free(extractable);
    if (sensitive)
        free(sensitive);
    if (always_sens)
        free(always_sens);
    if (never_extract)
        free(never_extract);

    return rc;
}

CK_RV token_specific_reencrypt_single(STDLL_TokData_t *tokdata,
                                      SESSION *session,
                                      ENCR_DECR_CONTEXT *decr_ctx,
                                      CK_MECHANISM *decr_mech,
                                      OBJECT *decr_key_obj,
                                      ENCR_DECR_CONTEXT *encr_ctx,
                                      CK_MECHANISM *encr_mech,
                                      OBJECT *encr_key_obj,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_ATTRIBUTE *decr_key_opaque, *encr_key_opaque;
    long return_code, reason_code, rule_array_count = 0;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
    CK_BYTE in_iv[AES_BLOCK_SIZE] = { 0 };
    CK_BYTE out_iv[AES_BLOCK_SIZE] = { 0 };
    long in_iv_len = 0, out_iv_len = 0;
    CK_BYTE cv[128] = { 0 };
    long cv_len = 128, zero = 0;
    CK_ULONG max_clear_len, req_out_len;
    CK_RV rc;

    UNUSED(session);
    UNUSED(decr_ctx);
    UNUSED(encr_ctx);

    if (((struct cca_private_data *)tokdata->private_data)->inconsistent) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = template_attribute_get_non_empty(decr_key_obj->template,
                                          CKA_IBM_OPAQUE, &decr_key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the decryption key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(encr_key_obj->template,
                                          CKA_IBM_OPAQUE, &encr_key_opaque);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the encryption key.\n");
        return rc;
    }

    /* CCA only supports AES-ECB/CBC, and 3DES-CBC with CSNBCTT2 */
    switch (decr_mech->mechanism) {
    case CKM_AES_ECB:
        rule_array_count = 2;
        memcpy(rule_array, "IKEY-AESI-ECB   ", 2 * CCA_KEYWORD_SIZE);

        max_clear_len = in_data_len;
        break;
    case CKM_AES_CBC:
        rule_array_count = 2;
        memcpy(rule_array, "IKEY-AESI-CBC   ", 2 * CCA_KEYWORD_SIZE);

        in_iv_len = decr_mech->ulParameterLen;
        if (in_iv_len != AES_BLOCK_SIZE)
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(in_iv, decr_mech->pParameter, in_iv_len);

        max_clear_len = in_data_len;
        break;
    case CKM_AES_CBC_PAD:
        rule_array_count = 2;
        memcpy(rule_array, "IKEY-AESIPKCSPAD", 2 * CCA_KEYWORD_SIZE);

        in_iv_len = decr_mech->ulParameterLen;
        if (in_iv_len != AES_BLOCK_SIZE)
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(in_iv, decr_mech->pParameter, in_iv_len);

        /* PKCS#7 pads at least 1 byte in any case */
        max_clear_len = in_data_len - 1;
        break;
    case CKM_DES3_CBC:
        rule_array_count = 2;
        memcpy(rule_array, "IKEY-DESI-CBC   ", 2 * CCA_KEYWORD_SIZE);

        in_iv_len = decr_mech->ulParameterLen;
        if (in_iv_len != DES_BLOCK_SIZE)
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(in_iv, decr_mech->pParameter, in_iv_len);

        max_clear_len = in_data_len;
        break;
    default:
        TRACE_DEVEL("Decryption method %lu not supported\n",
                     decr_mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    switch (encr_mech->mechanism) {
    case CKM_AES_ECB:
        memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
               "OKEY-AESO-ECB   ", 2 * CCA_KEYWORD_SIZE);
        rule_array_count += 2;

        /* Round up to the next block size */
        req_out_len = (max_clear_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE +
                (max_clear_len % AES_BLOCK_SIZE ? AES_BLOCK_SIZE : 0);
        break;
    case CKM_AES_CBC:
        memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
               "OKEY-AESO-CBC   ", 2 * CCA_KEYWORD_SIZE);
        rule_array_count += 2;

        out_iv_len = encr_mech->ulParameterLen;
        if (out_iv_len != AES_BLOCK_SIZE)
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(out_iv, encr_mech->pParameter, out_iv_len);

        /* Round up to the next block size */
        req_out_len = (max_clear_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE +
                (max_clear_len % AES_BLOCK_SIZE ? AES_BLOCK_SIZE : 0);
        break;
    case CKM_AES_CBC_PAD:
        memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
               "OKEY-AESOPKCSPAD", 2 * CCA_KEYWORD_SIZE);
        rule_array_count += 2;

        out_iv_len = encr_mech->ulParameterLen;
        if (out_iv_len != AES_BLOCK_SIZE)
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(out_iv, encr_mech->pParameter, out_iv_len);

        /* PKCS#7 pads a full block, if already a multiple of the block size */
        req_out_len = AES_BLOCK_SIZE * (max_clear_len / AES_BLOCK_SIZE + 1);
        break;
    case CKM_DES3_CBC:
        memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
               "OKEY-DESO-CBC   ", 2 * CCA_KEYWORD_SIZE);
        rule_array_count += 2;

        out_iv_len = encr_mech->ulParameterLen;
        if (out_iv_len != DES_BLOCK_SIZE)
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(out_iv, encr_mech->pParameter, out_iv_len);

        /* Round up to the next block size */
        req_out_len = (max_clear_len / DES_BLOCK_SIZE) * DES_BLOCK_SIZE +
                (max_clear_len % DES_BLOCK_SIZE ? DES_BLOCK_SIZE : 0);
        break;
    default:
        TRACE_DEVEL("Encryption method %lu not supported\n",
                     decr_mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    if (out_data == NULL) {
        *out_data_len = req_out_len;
        return CKR_OK;
    }

    if (*out_data_len < req_out_len) {
        *out_data_len = req_out_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNBCTT2(&return_code, &reason_code, NULL, NULL, &rule_array_count,
                     rule_array, (long *)&decr_key_opaque->ulValueLen,
                     decr_key_opaque->pValue, &in_iv_len, in_iv,
                     (long *)&in_data_len, in_data, &cv_len, cv,
                     (long *)&encr_key_opaque->ulValueLen, encr_key_opaque->pValue,
                     &out_iv_len, out_iv, (long *)out_data_len, out_data,
                     &zero, NULL, &zero, NULL);
    RETRY_NEW_MK_BLOB2_END(tokdata, return_code, reason_code,
                           encr_key_opaque->pValue, encr_key_opaque->ulValueLen,
                           decr_key_opaque->pValue, decr_key_opaque->ulValueLen);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBCTT2 (CIPHER TEXT TRANSLATE) failed."
                    " return:%ld, reason:%ld\n", return_code, reason_code);
        if (return_code == 8 && reason_code == 72)
            return CKR_DATA_LEN_RANGE;
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV file_fgets(const char *fname, char *buf, size_t buflen)
{
    FILE *fp;
    char *end;
    CK_RV rc = CKR_OK;

    buf[0] = '\0';

    fp = fopen(fname, "r");
    if (fp == NULL) {
        TRACE_ERROR("Failed to open file '%s'\n", fname);
        return CKR_FUNCTION_FAILED;
    }
    if (fgets(buf, buflen, fp) == NULL) {
        TRACE_ERROR("Failed to read from file '%s'\n", fname);
        rc = CKR_FUNCTION_FAILED;
        goto out_fclose;
    }

    end = memchr(buf, '\n', buflen);
    if (end)
        *end = 0;
    else
        buf[buflen - 1] = 0;

    if (strlen(buf) == 0)
        rc = CKR_FUNCTION_FAILED;

out_fclose:
    fclose(fp);
    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV cca_handle_apqn_event(STDLL_TokData_t *tokdata,
                                   unsigned int event_type,
                                   event_udev_apqn_data_t *apqn_data)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    char fname[290];
    char buf[250];
    CK_RV rc;
    unsigned long val;
#ifndef NO_PKEY
    unsigned int min_card_version;
#endif

    UNUSED(event_type);

    sprintf(fname, "%scard%02x/ap_functions", SYSFS_DEVICES_AP, apqn_data->card);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return CKR_OK;
    if (sscanf(buf, "%lx", &val) != 1)
        val = 0x00000000;
    if ((val & MASK_COPRO) == 0)
        return CKR_OK;

    TRACE_DEVEL("%s Cross checking MKVPs due to event for APQN %02X.%04X\n",
                __func__, apqn_data->card, apqn_data->domain);

    rc = cca_check_mks(tokdata);
    if (rc != CKR_OK) {
        if (__sync_fetch_and_or(&cca_private->inconsistent, TRUE) == FALSE) {
            TRACE_ERROR("CCA master key setup is inconsistent, all crypto operations will fail from now on\n");
            OCK_SYSLOG(LOG_ERR, "CCA master key setup is inconsistent, all crypto operations will fail from now on\n");
        }
        return CKR_OK;
    }

    if (__sync_fetch_and_and(&cca_private->inconsistent, FALSE) == TRUE) {
        TRACE_INFO("CCA master key setup is now consistent again\n");
        OCK_SYSLOG(LOG_INFO, "CCA master key setup is now consistent again\n");
    }

    /* Get ACP infos again after APQN set changed */
    rc = cca_get_acp_infos(tokdata);
    if (rc != CKR_OK) {
        TRACE_WARNING("Could not re-determine min ACP settings\n");
        return rc;
    }

    /* Re-check after APQN set change if protected key support is available */
    rc = cca_get_min_card_level(tokdata);
    if (rc != CKR_OK) {
        TRACE_WARNING("Could not re-determine min card level, protected key support not available.\n");
        return rc;
    }

#ifndef NO_PKEY
    /* Read min card version from CCA private data. Needs a read lock.*/
    if (pthread_rwlock_rdlock(&cca_private->min_card_version_rwlock) != 0) {
        TRACE_ERROR("CCA min_card_version RD-Lock failed.\n");
        return CKR_CANT_LOCK;
    }
    min_card_version = cca_private->min_card_version.ver;
    if (pthread_rwlock_unlock(&cca_private->min_card_version_rwlock) != 0) {
        TRACE_ERROR("CCA min_card_version RD-Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    /* Check minimum card version, XPRTCPAC requires min CEX7C */
    if (min_card_version < 7) {
        TRACE_WARNING("Min card version now is %d, protected key support not available on this system.\n",
                   cca_private->min_card_version.ver);
        /* Disable pkey */
        __sync_and_and_fetch(&cca_private->pkey_wrap_supported, 0);
    } else if (cca_private->pkey_wrap_supported == 0 &&
               !ccatok_pkey_option_disabled(tokdata)) {
        /* get firmware WKVP, this will enable PKEY on success */
        rc = ccatok_pkey_get_firmware_wkvp(tokdata);
        if (rc != CKR_OK) {
            OCK_SYSLOG(LOG_WARNING,
                "%s: Warning: Could not get wkvp, protected key support not available.\n",
                __func__);
            TRACE_WARNING("Could not get wkvp, protected key support not available.\n");
        }
    }
#endif /* NO_PKEY */

    return CKR_OK;
}

/*
 * Called by the event thread, on receipt of an event.
 *
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
CK_RV token_specific_handle_event(STDLL_TokData_t *tokdata,
                                  unsigned int event_type,
                                  unsigned int event_flags,
                                  const char *payload,
                                  unsigned int payload_len)
{
    UNUSED(event_flags);

    switch (event_type) {
    case EVENT_TYPE_APQN_ADD:
    case EVENT_TYPE_APQN_REMOVE:
        if (payload_len != sizeof(event_udev_apqn_data_t))
            return CKR_FUNCTION_FAILED;
        return cca_handle_apqn_event(tokdata, event_type,
                                     (event_udev_apqn_data_t *)payload);

    case EVENT_TYPE_MK_CHANGE_INITIATE_QUERY:
    case EVENT_TYPE_MK_CHANGE_REENCIPHER:
    case EVENT_TYPE_MK_CHANGE_FINALIZE_QUERY:
    case EVENT_TYPE_MK_CHANGE_FINALIZE:
    case EVENT_TYPE_MK_CHANGE_CANCEL_QUERY:
    case EVENT_TYPE_MK_CHANGE_CANCEL:
        return cca_handle_mk_change_event(tokdata, event_type, event_flags,
                                          payload, payload_len);

    default:
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return CKR_OK;
}

static CK_RV cca_convert_aes_data_to_cipher_key(STDLL_TokData_t *tokdata,
                                                SESSION *session,
                                                OBJECT *obj,
                                                CK_BBOOL is_xts)
{
    long return_code, reason_code, rule_array_count, target_key_len;
    unsigned char target_key_token[CCA_MAX_AES_CIPHER_KEY_SIZE * 2] = { 0 };
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
    unsigned char null_token[64] = { 0, };
    long null_token_len = sizeof(null_token);
    long reserved_1 = 0, key_part1_len, inp_key_len;
    enum cca_token_type keytype, keytype2;
    unsigned int keybitsize, keybitsize2;
    const CK_BYTE *mkvp, *mkvp2;
    CK_BBOOL new_mk, new_mk2;
    CK_ATTRIBUTE *attr, *reenc_attr = NULL;
    CK_ULONG key_size;
    CK_IBM_CCA_AES_KEY_MODE_TYPE mode = CK_IBM_CCA_AES_CIPHER_KEY;
    CK_RV rc;

    UNUSED(session);

    rc = template_attribute_get_non_empty(obj->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s CKA_IBM_OPAQUE is missing\n", __func__);
        return rc;
    }

    key_size = (is_xts ? attr->ulValueLen / 2 : attr->ulValueLen);

    if (analyse_cca_key_token(attr->pValue, key_size,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token\n");
        return CKR_FUNCTION_FAILED;
    }

    switch (keytype) {
    case sec_aes_data_key:
        break;
    case sec_aes_cipher_key:
        /* Already a CIPHER key, nothing to do */
        return CKR_OK;
    default:
        TRACE_ERROR("Invalid/unknown cca token\n");
        return CKR_FUNCTION_FAILED;
    }

retry:
    memcpy(rule_array, "INTERNALAES     CIPHER  ANY-MODE",
           4 * CCA_KEYWORD_SIZE);
    rule_array_count = 4;

    rc = cca_aes_cipher_add_key_usage_keywords(tokdata, obj->template,
                                               rule_array, sizeof(rule_array),
                                               (CK_ULONG *)&rule_array_count);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to add key usage keywords\n");
        return rc;
    }

    target_key_len = sizeof(target_key_token) / 2;
    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL,
                     &rule_array_count, rule_array,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &reserved_1, NULL,
                     &target_key_len, target_key_token);
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBKTB2 (AES CIPHER KEY TOKEN BUILD) failed."
                    " return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(rule_array, "AES     REFORMAT", 2 * CCA_KEYWORD_SIZE);
    rule_array_count = 2;

    target_key_len = sizeof(target_key_token) / 2;
    inp_key_len = key_size;
    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        dll_CSNBKTR2(&return_code, &reason_code, NULL, NULL,
                     &rule_array_count, rule_array,
                     &inp_key_len, attr->pValue,
                     &null_token_len, null_token,
                     &reserved_1, NULL,
                     &target_key_len, target_key_token);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, key_size)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBKTR2 (KEY TRANSLATE2) failed."
                    " return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    if (analyse_cca_key_token(target_key_token, target_key_len,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL || keytype != sec_aes_cipher_key) {
        TRACE_ERROR("Invalid/unknown cca token has been imported\n");
        return CKR_FUNCTION_FAILED;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        return CKR_DEVICE_ERROR;
    }

    rc = cca_reencipher_created_key(tokdata, obj->template,
                                    target_key_token, target_key_len, new_mk,
                                    keytype, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        return rc;
    }

    if (is_xts) {
        key_part1_len = target_key_len;

        memcpy(rule_array, "INTERNALAES     CIPHER  ANY-MODE",
               4 * CCA_KEYWORD_SIZE);
        rule_array_count = 4;

        rc = cca_aes_cipher_add_key_usage_keywords(tokdata, obj->template,
                                                   rule_array,
                                                   sizeof(rule_array),
                                                   (CK_ULONG *)
                                                           &rule_array_count);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to add key usage keywords\n");
            return rc;
        }

        target_key_len = sizeof(target_key_token) - key_part1_len;
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL,
                         &rule_array_count, rule_array,
                         &reserved_1, NULL,
                         &reserved_1, NULL,
                         &reserved_1, NULL,
                         &reserved_1, NULL,
                         &reserved_1, NULL,
                         &target_key_len, target_key_token + key_part1_len);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBKTB2 (AES CIPHER KEY TOKEN BUILD) failed."
                        " return:%ld, reason:%ld\n",
                        return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        memcpy(rule_array, "AES     REFORMAT", 2 * CCA_KEYWORD_SIZE);
        rule_array_count = 2;

        target_key_len = sizeof(target_key_token) - key_part1_len;
        inp_key_len = key_size;
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            dll_CSNBKTR2(&return_code, &reason_code, NULL, NULL,
                         &rule_array_count, rule_array,
                         &inp_key_len, attr->pValue,
                         &null_token_len, null_token,
                         &reserved_1, NULL,
                         &target_key_len, target_key_token + key_part1_len);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              attr->pValue, key_size)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBKTR2 (KEY TRANSLATE2) failed."
                        " return:%ld, reason:%ld\n",
                        return_code, reason_code);
            return CKR_FUNCTION_FAILED;
        }

        if (analyse_cca_key_token(target_key_token + key_part1_len,
                                  target_key_len,
                                  &keytype2, &keybitsize2, &mkvp2) == FALSE ||
            mkvp2 == NULL || keytype2 != sec_aes_cipher_key) {
            TRACE_ERROR("Invalid/unknown cca token has been imported\n");
            return CKR_FUNCTION_FAILED;
        }

        if (check_expected_mkvp(tokdata, keytype2, mkvp2, &new_mk2) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            return CKR_DEVICE_ERROR;
        }

        if (new_mk == FALSE && new_mk2 == TRUE) {
            /*
             * Key 2 was created with new MK, key 1 with old MK.
             * Key 2 will have CKA_IBM_OPAQUE and CKA_IBM_OPAQUE_REENC both
             * with new MK (will be set by cca_reencipher_created_key() below).
             * Key 1 has CKA_IBM_OPAQUE with old MK, and CKA_IBM_OPAQUE_REENC
             * with new MK (it was re-enciphered by cca_reencipher_created_key()
             * above). Supply CKA_IBM_OPAQUE_REENC with new MK in CKA_IBM_OPAQUE
             * for key 1 also, so that both, CKA_IBM_OPAQUE and
             * CKA_IBM_OPAQUE_REENC have new MK only for both key parts.
             */
            rc = template_attribute_get_non_empty(obj->template,
                                                  CKA_IBM_OPAQUE_REENC,
                                                  &reenc_attr);
            if (rc != CKR_OK || reenc_attr == NULL ||
                reenc_attr->ulValueLen != (CK_ULONG)key_part1_len) {
                TRACE_ERROR("No CKA_IBM_OPAQUE_REENC attr found\n");
                return CKR_TEMPLATE_INCOMPLETE;
            }

            memcpy(target_key_token, reenc_attr->pValue, key_part1_len);
        } else if (new_mk == TRUE && new_mk2 == FALSE) {
            /*
             * Key 1 was created with new MK, but key 2 with old MK.
             * This can happen when an APQN with new MK went offline
             * and another APQN with old MK is selected after creating
             * key 1 but before creating key 2. Since there is no key 1 blob
             * with old MK in CKA_IBM_OPAQUE, we need to re-create both keys
             * (both with old MK now).
             */
            memset(target_key_token, 0, sizeof(target_key_token));
            goto retry;
        }

        rc = cca_reencipher_created_key(tokdata, obj->template,
                                        target_key_token + key_part1_len,
                                        target_key_len, new_mk2,
                                        keytype2, TRUE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            return rc;
        }

        if (memcmp(mkvp, mkvp2, CCA_MKVP_LENGTH) != 0 ||
            keybitsize != keybitsize2) {
            TRACE_ERROR("CCA AES XTS keys attribute value mismatch\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        target_key_len += key_part1_len;
    }

    rc = build_update_attribute(obj->template, CKA_IBM_OPAQUE,
                                target_key_token, target_key_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE) failed\n");
        return rc;
    }

    rc = build_update_attribute(obj->template, CKA_IBM_CCA_AES_KEY_MODE,
                                (CK_BYTE *)&mode, sizeof(mode));
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_update_attribute(CKA_IBM_CCA_AES_KEY_MODE) failed\n");
        return rc;
    }

    return CKR_OK;
}

CK_RV token_specific_set_attribute_values(STDLL_TokData_t *tokdata,
                                          SESSION *session,
                                          OBJECT *obj,
                                          TEMPLATE *new_tmpl)
{
    long return_code, reason_code;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    unsigned char exit_data[4];
    long rule_array_count, exit_data_len = 0, zero = 0, key_len;
    enum cca_token_type keytype, keytype2;
    unsigned int keybitsize, keybitsize2;
    const CK_BYTE *mkvp, *mkvp2;
    CK_BBOOL new_mk, new_mk2;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE ktype;
    DL_NODE *node;
    CK_ATTRIBUTE *attr, *reenc_attr;
    CK_ULONG key_size;
    CK_RV rc;

    UNUSED(session);

    rc = template_attribute_get_ulong(obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s CKA_CLASS is missing\n", __func__);
        return rc;
    }

    switch (class) {
    case CKO_SECRET_KEY:
    case CKO_PRIVATE_KEY:
    case CKO_PUBLIC_KEY:
        break;
    default:
        /* Not a key, nothing to do */
        return CKR_OK;
    }

    rc = template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &ktype);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s CKA_KEY_TYPE is missing\n", __func__);
        return rc;
    }

    switch (ktype) {
    case CKK_AES:
    case CKK_AES_XTS:
        memcpy(rule_array, "AES     ", CCA_KEYWORD_SIZE);
        rule_array_count = 1;
        break;
    case CKK_GENERIC_SECRET:
        memcpy(rule_array, "HMAC    ", CCA_KEYWORD_SIZE);
        rule_array_count = 1;
        break;
    case CKK_EC:
        if (class != CKO_PRIVATE_KEY)
            return CKR_OK;
        return ccatok_check_ec_derive_info(tokdata, obj, new_tmpl);
    default:
        /* Not an AES or HMAC key, nothing to do */
        return CKR_OK;
    }

    node = new_tmpl->attribute_list;
    while (node) {
        attr = (CK_ATTRIBUTE *)node->data;

        switch (attr->type) {
        case CKA_EXTRACTABLE:
            if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }

            if (*((CK_BBOOL *)attr->pValue) != FALSE)
                continue;

            memcpy(rule_array + (rule_array_count * CCA_KEYWORD_SIZE),
                   "NOEX-SYMNOEXUASYNOEXAASYNOEX-DESNOEX-AESNOEX-RSA",
                   6 * CCA_KEYWORD_SIZE);
            rule_array_count += 6;
            break;

        case CKA_IBM_CCA_AES_KEY_MODE:
            if (ktype != CKK_AES && ktype != CKK_AES_XTS)
                break;

            if (attr->ulValueLen != sizeof(CK_IBM_CCA_AES_KEY_MODE_TYPE) ||
                attr->pValue == NULL ||
                *((CK_IBM_CCA_AES_KEY_MODE_TYPE *)attr->pValue) !=
                                                CK_IBM_CCA_AES_CIPHER_KEY) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }

            rc = cca_convert_aes_data_to_cipher_key(tokdata, session, obj,
                                                    ktype == CKK_AES_XTS);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s cca_convert_data_to_cipher_key failed "
                            "rc=0x%lx\n", __func__, rc);
                return rc;
            }
            break;
        }

        node = node->next;
    }

    if (rule_array_count == 1)
        return CKR_OK; /* Nothing to do */

    rc = template_attribute_get_non_empty(obj->template, CKA_IBM_OPAQUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s CKA_IBM_OPAQUE is missing\n", __func__);
        return rc;
    }

    key_size = (ktype == CKK_AES_XTS ? attr->ulValueLen / 2 : attr->ulValueLen);

    if (analyse_cca_key_token(attr->pValue, key_size,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token\n");
        return CKR_FUNCTION_FAILED;
    }

    if (keytype != sec_aes_cipher_key && keytype != sec_hmac_key)
        return CKR_OK; /* AES DATA key can not be restricted, nothing to do */

    rc = build_attribute(CKA_IBM_OPAQUE, attr->pValue, attr->ulValueLen,
                         &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed rc=0x%lx\n", __func__, rc);
        return rc;
    }

retry:
    USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
    RETRY_NEW_MK_BLOB_START()
        key_len = key_size;
        dll_CSNBRKA(&return_code, &reason_code,
                    &exit_data_len, exit_data,
                    &rule_array_count, rule_array,
                    &key_len, attr->pValue,
                    &zero, NULL, &zero, NULL, &zero, NULL);
    RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                          attr->pValue, key_size)
    USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSNBRKA (Restrict Key Attribute) failed."
                    " return:%ld, reason:%ld\n",
                    return_code, reason_code);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (analyse_cca_key_token(attr->pValue, key_size,
                              &keytype, &keybitsize, &mkvp) == FALSE ||
        mkvp == NULL) {
        TRACE_ERROR("Invalid/unknown cca token has been generated\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
        rc = CKR_DEVICE_ERROR;
        goto out;
    }

    rc = cca_reencipher_created_key(tokdata, obj->template,
                                    attr->pValue, key_size,
                                    new_mk, keytype, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
        goto out;
    }

    if (ktype == CKK_AES_XTS) {
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
        RETRY_NEW_MK_BLOB_START()
            key_len = key_size;
            dll_CSNBRKA(&return_code, &reason_code,
                        &exit_data_len, exit_data,
                        &rule_array_count, rule_array,
                        &key_len, (CK_BYTE *)attr->pValue + key_size,
                        &zero, NULL, &zero, NULL, &zero, NULL);
        RETRY_NEW_MK_BLOB_END(tokdata, return_code, reason_code,
                              (CK_BYTE *)attr->pValue + key_size, key_size)
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)

        if (return_code != CCA_SUCCESS) {
            TRACE_ERROR("CSNBRKA (Restrict Key Attribute) failed."
                        " return:%ld, reason:%ld\n",
                        return_code, reason_code);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        if (analyse_cca_key_token((CK_BYTE *)attr->pValue + key_size, key_size,
                                  &keytype2, &keybitsize2, &mkvp2) == FALSE ||
            mkvp2 == NULL) {
            TRACE_ERROR("Invalid/unknown cca token has been generated\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        if (check_expected_mkvp(tokdata, keytype2, mkvp2, &new_mk2) != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));
            rc = CKR_DEVICE_ERROR;
            goto out;
        }

        if (new_mk == FALSE && new_mk2 == TRUE) {
            /*
             * Key 2 was created with new MK, key 1 with old MK.
             * Key 2 will have CKA_IBM_OPAQUE and CKA_IBM_OPAQUE_REENC both
             * with new MK (will be set by cca_reencipher_created_key() below).
             * Key 1 has CKA_IBM_OPAQUE with old MK, and CKA_IBM_OPAQUE_REENC
             * with new MK (it was re-enciphered by cca_reencipher_created_key()
             * above). Supply CKA_IBM_OPAQUE_REENC with new MK in CKA_IBM_OPAQUE
             * for key 1 also, so that both, CKA_IBM_OPAQUE and
             * CKA_IBM_OPAQUE_REENC have new MK only for both key parts.
             */
            rc = template_attribute_get_non_empty(obj->template,
                                                  CKA_IBM_OPAQUE_REENC,
                                                  &reenc_attr);
            if (rc != CKR_OK || reenc_attr == NULL ||
                reenc_attr->ulValueLen != key_size) {
                TRACE_ERROR("No CKA_IBM_OPAQUE_REENC attr found\n");
                return CKR_TEMPLATE_INCOMPLETE;
            }

            memcpy(attr->pValue, reenc_attr->pValue, key_size);
        } else if (new_mk == TRUE && new_mk2 == FALSE) {
            /*
             * Key 1 was created with new MK, but key 2 with old MK.
             * This can happen when an APQN with new MK went offline
             * and another APQN with old MK is selected after creating
             * key 1 but before creating key 2. Since there is no key 1 blob
             * with old MK in CKA_IBM_OPAQUE, we need to re-create both keys
             * (both with old MK now).
             */
            memset(attr->pValue, 0, sizeof(key_size));
            goto retry;
        }

        rc = cca_reencipher_created_key(tokdata, obj->template,
                                        (CK_BYTE *)attr->pValue + key_size,
                                        key_size, new_mk2, keytype2, TRUE);
        if (rc != CKR_OK) {
            TRACE_ERROR("cca_reencipher_created_key failed: 0x%lx\n", rc);
            goto out;
        }

        if (keytype != keytype2 ||
            memcmp(mkvp, mkvp2, CCA_MKVP_LENGTH) != 0 ||
            keybitsize != keybitsize2) {
            TRACE_ERROR("CCA AES XTS keys attribute value mismatch\n");
            rc = CKR_ATTRIBUTE_VALUE_INVALID;
            goto out;
        }
    }

    rc = template_update_attribute(obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed rc=0x%lx\n",
                    __func__, rc);
        goto out;
    }
    attr = NULL;

out:
    if (attr != NULL)
        free(attr);

    return rc;
}
