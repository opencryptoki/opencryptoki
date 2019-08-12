/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*----------------------------------------------------------------------
 *  IBM Research & Development
 *  Author: Urban, Volker (volker.urban@de.ibm.com)
 *----------------------------------------------------------------------*/

#if ! defined(__EP11_H__)
#define __EP11_H__

#if !defined(CKR_OK)            /* don't assume include guards */
#include "pkcs11.h"
#endif

#if !defined(INT64_MIN)
#error "We need 64-bit <stdint.h> types, please include before this file."
#endif

// SHA224 etc. are additions to PKCS#11 2.20
// remove these when host migrates beyond 2.20
//
#if !defined(CKM_SHA224)
#define  CKM_SHA224                 0x00000255
#define  CKM_SHA224_HMAC            0x00000256
#define  CKM_SHA224_HMAC_GENERAL    0x00000257
#define  CKM_SHA224_RSA_PKCS        0x00000046
#define  CKM_SHA224_RSA_PKCS_PSS    0x00000047
#define  CKM_SHA224_KEY_DERIVATION  0x00000396
#define  CKM_AES_CTR                0x00001086
#define  CKG_MGF1_SHA224            0x00000005
#endif

#if !defined(CKM_AES_CMAC)
#define  CKM_AES_CMAC               0x0000108a
#endif

#if !defined(CKM_ALG_DES3_CMAC)
#define  CKM_DES3_CMAC              0x00000138
#endif

typedef uint64_t target_t;

/*----------------------------------------------------------------------
 *  CK_... type arguments correspond to the original PKCS#11 call's
 *  arguments.  Standard types mean PKCS#11 objects (session, token etc.)
 *  are mapped to a native type (key blob, mechanism) etc.
 *
 *  As an example, for _Encrypt and _Decrypt, a session is passed to
 *  the PKCS#11 function.  This session needs to be matched to a key blob,
 *  so our _Encrypt interface takes a key/keylen buffer instead of the
 *  session.  All other parameters should be passed through unchanged.
 *
 *  For certain operations, such as _GenerateKey, there are no real
 *  PKCS#11 type parameters at this level.
 */

CK_RV m_GenerateRandom(CK_BYTE_PTR rnd, CK_ULONG len, target_t target);

/* note: external seeding not supported */
CK_RV m_SeedRandom(CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen, target_t target);
CK_RV m_DigestInit(unsigned char *state, size_t * len,
                   const CK_MECHANISM_PTR pmech, target_t target);

CK_RV m_Digest(const unsigned char *state, size_t slen,
               CK_BYTE_PTR data, CK_ULONG len,
               CK_BYTE_PTR digest, CK_ULONG_PTR dglen, target_t target);
CK_RV m_DigestUpdate(unsigned char *state, size_t slen,
                     CK_BYTE_PTR data, CK_ULONG dlen, target_t target);
CK_RV m_DigestKey(unsigned char *state, size_t slen,
                  const unsigned char *key, size_t klen, target_t target);
CK_RV m_DigestFinal(const unsigned char *state, size_t slen,
                    CK_BYTE_PTR digest, CK_ULONG_PTR dlen, target_t target);
CK_RV m_DigestSingle(CK_MECHANISM_PTR pmech,
                     CK_BYTE_PTR data, CK_ULONG len,
                     CK_BYTE_PTR digest, CK_ULONG_PTR dlen, target_t target);

CK_RV m_EncryptInit(unsigned char *state, size_t * slen,
                    CK_MECHANISM_PTR pmech,
                    const unsigned char *key, size_t klen, target_t target);
CK_RV m_DecryptInit(unsigned char *state, size_t * slen,
                    CK_MECHANISM_PTR pmech,
                    const unsigned char *key, size_t klen, target_t target);

CK_RV m_EncryptUpdate(unsigned char *state, size_t slen,
                      CK_BYTE_PTR plain, CK_ULONG plen,
                      CK_BYTE_PTR cipher, CK_ULONG_PTR clen, target_t target);
CK_RV m_DecryptUpdate(unsigned char *state, size_t slen,
                      CK_BYTE_PTR cipher, CK_ULONG clen,
                      CK_BYTE_PTR plain, CK_ULONG_PTR plen, target_t target);

/* one-pass en/decrypt with key blob */
CK_RV m_Encrypt(const unsigned char *state, size_t slen,
                CK_BYTE_PTR plain, CK_ULONG plen,
                CK_BYTE_PTR cipher, CK_ULONG_PTR clen, target_t target);
CK_RV m_Decrypt(const unsigned char *state, size_t slen,
                CK_BYTE_PTR cipher, CK_ULONG clen,
                CK_BYTE_PTR plain, CK_ULONG_PTR plen, target_t target);

CK_RV m_EncryptFinal(const unsigned char *state, size_t slen,
                     CK_BYTE_PTR output, CK_ULONG_PTR len, target_t target);
CK_RV m_DecryptFinal(const unsigned char *state, size_t slen,
                     CK_BYTE_PTR output, CK_ULONG_PTR len, target_t target);

/* en/decrypt directly with key blob */
CK_RV m_EncryptSingle(const unsigned char *key, size_t klen,
                      CK_MECHANISM_PTR mech,
                      CK_BYTE_PTR plain, CK_ULONG plen,
                      CK_BYTE_PTR cipher, CK_ULONG_PTR clen, target_t target);
CK_RV m_DecryptSingle(const unsigned char *key, size_t klen,
                      CK_MECHANISM_PTR mech,
                      CK_BYTE_PTR cipher, CK_ULONG clen,
                      CK_BYTE_PTR plain, CK_ULONG_PTR plen, target_t target);

/* de+encrypt in one pass, without exposing cleartext */
CK_RV m_ReencryptSingle(const unsigned char *dkey, size_t dklen,
                        const unsigned char *ekey, size_t eklen,
                        CK_MECHANISM_PTR pdecrmech,
                        CK_MECHANISM_PTR pencrmech,
                        CK_BYTE_PTR in, CK_ULONG ilen,
                        CK_BYTE_PTR out, CK_ULONG_PTR olen, target_t target);

CK_RV m_GenerateKey(CK_MECHANISM_PTR pmech,
                    CK_ATTRIBUTE_PTR ptempl, CK_ULONG templcount,
                    const unsigned char *pin, size_t pinlen,
                    unsigned char *key, size_t * klen,
                    unsigned char *csum, size_t * clen, target_t target);

CK_RV m_GenerateKeyPair(CK_MECHANISM_PTR pmech,
                        CK_ATTRIBUTE_PTR ppublic, CK_ULONG pubattrs,
                        CK_ATTRIBUTE_PTR pprivate, CK_ULONG prvattrs,
                        const unsigned char *pin, size_t pinlen,
                        unsigned char *key, size_t * klen,
                        unsigned char *pubkey, size_t * pklen, target_t target);

CK_RV m_SignInit(unsigned char *state, size_t * slen,
                 CK_MECHANISM_PTR alg,
                 const unsigned char *key, size_t klen, target_t target);
CK_RV m_VerifyInit(unsigned char *state, size_t * slen,
                   CK_MECHANISM_PTR alg,
                   const unsigned char *key, size_t klen, target_t target);

CK_RV m_SignUpdate(unsigned char *state, size_t slen,
                   CK_BYTE_PTR data, CK_ULONG dlen, target_t target);
CK_RV m_VerifyUpdate(unsigned char *state, size_t slen,
                     CK_BYTE_PTR data, CK_ULONG dlen, target_t target);

CK_RV m_SignFinal(const unsigned char *state, size_t stlen,
                  CK_BYTE_PTR sig, CK_ULONG_PTR siglen, target_t target);
CK_RV m_VerifyFinal(const unsigned char *state, size_t stlen,
                    CK_BYTE_PTR sig, CK_ULONG siglen, target_t target);

CK_RV m_Sign(const unsigned char *state, size_t stlen,
             CK_BYTE_PTR data, CK_ULONG dlen,
             CK_BYTE_PTR sig, CK_ULONG_PTR siglen, target_t target);
CK_RV m_Verify(const unsigned char *state, size_t stlen,
               CK_BYTE_PTR data, CK_ULONG dlen,
               CK_BYTE_PTR sig, CK_ULONG siglen, target_t target);

CK_RV m_SignSingle(const unsigned char *key, size_t klen,
                   CK_MECHANISM_PTR pmech,
                   CK_BYTE_PTR data, CK_ULONG dlen,
                   CK_BYTE_PTR sig, CK_ULONG_PTR slen, target_t target);
CK_RV m_VerifySingle(const unsigned char *key, size_t klen,
                     CK_MECHANISM_PTR pmech,
                     CK_BYTE_PTR data, CK_ULONG dlen,
                     CK_BYTE_PTR sig, CK_ULONG slen, target_t target);

/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
CK_RV m_WrapKey(const unsigned char *key, size_t keylen,
                const unsigned char *kek, size_t keklen,
                const unsigned char *mackey, size_t mklen,
                const CK_MECHANISM_PTR pmech,
                CK_BYTE_PTR wrapped, CK_ULONG_PTR wlen, target_t target);

/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
CK_RV m_UnwrapKey(const CK_BYTE_PTR wrapped, CK_ULONG wlen,
                  const unsigned char *kek, size_t keklen,
                  const unsigned char *mackey, size_t mklen,
                  const unsigned char *pin, size_t pinlen,
                  const CK_MECHANISM_PTR uwmech,
                  const CK_ATTRIBUTE_PTR ptempl, CK_ULONG pcount,
                  unsigned char *unwrapped, size_t * uwlen,
                  CK_BYTE_PTR csum, CK_ULONG * cslen, target_t target);

CK_RV m_DeriveKey(CK_MECHANISM_PTR pderivemech,
                  CK_ATTRIBUTE_PTR ptempl, CK_ULONG templcount,
                  const unsigned char *basekey, size_t bklen,
                  const unsigned char *data, size_t dlen,
                  const unsigned char *pin, size_t pinlen,
                  unsigned char *newkey, size_t * nklen,
                  unsigned char *csum, size_t * cslen, target_t target);


CK_RV m_GetMechanismList(CK_SLOT_ID slot,
                         CK_MECHANISM_TYPE_PTR mechs,
                         CK_ULONG_PTR count, target_t target);
CK_RV m_GetMechanismInfo(CK_SLOT_ID slot,
                         CK_MECHANISM_TYPE mech,
                         CK_MECHANISM_INFO_PTR pmechinfo, target_t target);

CK_RV m_GetAttributeValue(const unsigned char *obj, size_t olen,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          target_t target);
CK_RV m_SetAttributeValue(unsigned char *obj, size_t olen,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          target_t target);


CK_RV m_Login(CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
              const unsigned char *nonce, size_t nlen,
              unsigned char *pinblob, size_t * pinbloblen, target_t target);
CK_RV m_Logout(const unsigned char *pin, size_t len, target_t target);

CK_RV m_admin(unsigned char *response1, size_t * r1len,
              unsigned char *response2, size_t * r2len,
              const unsigned char *cmd, size_t clen,
              const unsigned char *sigs, size_t slen, target_t target);


/*--------------------------------------------------------------------------
 *  Module management.
 */

typedef struct XCP_ModuleSocket {
    char host[256 + 1];
    uint32_t port;
} *XCP_ModuleSocket_t;

typedef struct XCP_DomainPerf {
    unsigned int lastperf[256];
} *XCP_DomainPerf_t;

typedef struct XCP_Module {
    uint32_t version;
    uint64_t flags;
    uint32_t domains;
    unsigned char domainmask[256 /8];
    struct XCP_ModuleSocket socket;
    uint32_t module_nr;
    void *mhandle;
    struct XCP_DomainPerf perf;
} *XCP_Module_t ;

typedef enum {
    XCP_MFL_SOCKET       =    1,
    XCP_MFL_MODULE       =    2,
    XCP_MFL_MHANDLE      =    4,
    XCP_MFL_PERF         =    8,
    XCP_MFL_VIRTUAL      = 0x10,
    XCP_MFL_STRICT       = 0x20,
    XCP_MFL_PROBE        = 0x40,
    XCP_MFL_ALW_TGT_ADD  = 0x80,
    XCP_MFL_MAX          = 0xff
} XCP_Module_Flags;

#define XCP_MOD_VERSION     1
#define XCP_TGT_INIT        ~0UL

#define XCPTGTMASK_SET_DOM(mask, domain)      \
                           mask[((domain)/8)] |=   (1 << (7-(domain)%8))

int m_add_backend(const char *name, unsigned int port);
int m_init(void);
int m_shutdown(void);
int m_add_module(XCP_Module_t module, target_t *target);
int m_rm_module(XCP_Module_t module, target_t target);


#endif                          /* n defined(__EP11_H__) */
