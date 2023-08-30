/*
 * COPYRIGHT (c) International Business Machines Corp. 2016-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef EP11_FUNC_H
#define EP11_FUNC_H

/*
 * I dont see a better way than to ignore this warning for now.
 * Note that the GCC pragma also works for clang.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#include "ep11.h"
#include "ep11adm.h"

#pragma GCC diagnostic pop

#define XCP_MOD_VERSION_1           1
#define XCP_MOD_VERSION_2           2

/* mechanisms defined by EP11 with an invalid (outdated) ID */
#define CKM_EP11_SHA512_224                 0x000002B0  // 0x00000048 in PKCS#11
#define CKM_EP11_SHA512_224_HMAC            0x000002B1  // 0x00000049 in PKCS#11
#define CKM_EP11_SHA512_224_HMAC_GENERAL    0x000002B2  // 0x0000004A in PKCS#11
#define CKM_EP11_SHA512_256                 0x000002C0  // 0x0000004C in PKCS#11
#define CKM_EP11_SHA512_256_HMAC            0x000002C1  // 0x0000004D in PKCS#11
#define CKM_EP11_SHA512_256_HMAC_GENERAL    0x000002C2  // 0x0000004E in PKCS#11

/* EP11 specific mechanisms unknown by ock, known by EP11, but not in ep11.h */
#define CKM_IBM_SHA512_256_KEY_DERIVATION  CKM_VENDOR_DEFINED + 0x00010016
#define CKM_IBM_SHA512_224_KEY_DERIVATION  CKM_VENDOR_DEFINED + 0x00010017
#define CKM_IBM_EDDSA_PH_SHA512            CKM_VENDOR_DEFINED + 0x0001001D
#define CKM_IBM_SM3                        CKM_VENDOR_DEFINED + 0x0005000e

#define XCP_CPB_ALG_PQC_DILITHIUM          XCP_CPB_ALG_PQC

/* EP11 function types */
typedef CK_RV (*m_GenerateRandom_t) (CK_BYTE_PTR rnd, CK_ULONG len,
                                     target_t target);
typedef CK_RV (*m_SeedRandom_t) (CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen,
                                 target_t target);
typedef CK_RV (*m_Digest_t) (const unsigned char *state, size_t slen,
                             CK_BYTE_PTR data, CK_ULONG len,
                             CK_BYTE_PTR digest, CK_ULONG_PTR dglen,
                             target_t target);
typedef CK_RV (*m_DigestInit_t) (unsigned char *state, size_t * len,
                                 const CK_MECHANISM_PTR pmech,
                                 target_t target);
typedef CK_RV (*m_DigestUpdate_t) (unsigned char *state, size_t slen,
                                   CK_BYTE_PTR data, CK_ULONG dlen,
                                   target_t target);
typedef CK_RV (*m_DigestKey_t) (unsigned char *state, size_t slen,
                                const unsigned char *key, size_t klen,
                                target_t target);
typedef CK_RV (*m_DigestFinal_t) (const unsigned char *state,
                                  size_t slen, CK_BYTE_PTR digest,
                                  CK_ULONG_PTR dlen, target_t target);
typedef CK_RV (*m_DigestSingle_t) (CK_MECHANISM_PTR pmech,
                                   CK_BYTE_PTR data, CK_ULONG len,
                                   CK_BYTE_PTR digest, CK_ULONG_PTR dlen,
                                   target_t target);
typedef CK_RV (*m_EncryptInit_t) (unsigned char *state, size_t * slen,
                                  CK_MECHANISM_PTR pmech,
                                  const unsigned char *key, size_t klen,
                                  target_t target);
typedef CK_RV (*m_DecryptInit_t) (unsigned char *state, size_t * slen,
                                  CK_MECHANISM_PTR pmech,
                                  const unsigned char *key, size_t klen,
                                  target_t target);
typedef CK_RV (*m_EncryptUpdate_t) (unsigned char *state, size_t slen,
                                    CK_BYTE_PTR plain, CK_ULONG plen,
                                    CK_BYTE_PTR cipher,
                                    CK_ULONG_PTR clen, target_t target);
typedef CK_RV (*m_DecryptUpdate_t) (unsigned char *state, size_t slen,
                                    CK_BYTE_PTR cipher, CK_ULONG clen,
                                    CK_BYTE_PTR plain, CK_ULONG_PTR plen,
                                    target_t target);
typedef CK_RV (*m_Encrypt_t) (const unsigned char *state, size_t slen,
                              CK_BYTE_PTR plain, CK_ULONG plen,
                              CK_BYTE_PTR cipher, CK_ULONG_PTR clen,
                              target_t target);
typedef CK_RV (*m_Decrypt_t) (const unsigned char *state, size_t slen,
                              CK_BYTE_PTR cipher, CK_ULONG clen,
                              CK_BYTE_PTR plain, CK_ULONG_PTR plen,
                              target_t target);
typedef CK_RV (*m_EncryptFinal_t) (const unsigned char *state,
                                   size_t slen, CK_BYTE_PTR output,
                                   CK_ULONG_PTR len, target_t target);
typedef CK_RV (*m_DecryptFinal_t) (const unsigned char *state,
                                   size_t slen, CK_BYTE_PTR output,
                                   CK_ULONG_PTR len, target_t target);
typedef CK_RV (*m_EncryptSingle_t) (const unsigned char *key,
                                    size_t klen, CK_MECHANISM_PTR mech,
                                    CK_BYTE_PTR plain, CK_ULONG plen,
                                    CK_BYTE_PTR cipher,
                                    CK_ULONG_PTR clen, target_t target);
typedef CK_RV (*m_DecryptSingle_t) (const unsigned char *key,
                                    size_t klen, CK_MECHANISM_PTR mech,
                                    CK_BYTE_PTR cipher, CK_ULONG clen,
                                    CK_BYTE_PTR plain, CK_ULONG_PTR plen,
                                    target_t target);
typedef CK_RV (*m_ReencryptSingle_t) (const unsigned char *dkey,
                                      size_t dklen,
                                      const unsigned char *ekey,
                                      size_t eklen,
                                      CK_MECHANISM_PTR pdecrmech,
                                      CK_MECHANISM_PTR pencrmech,
                                      CK_BYTE_PTR in, CK_ULONG ilen,
                                      CK_BYTE_PTR out, CK_ULONG_PTR olen,
                                      target_t target);
typedef CK_RV (*m_GenerateKey_t) (CK_MECHANISM_PTR pmech,
                                  CK_ATTRIBUTE_PTR ptempl,
                                  CK_ULONG templcount,
                                  const unsigned char *pin,
                                  size_t pinlen, unsigned char *key,
                                  size_t * klen, unsigned char *csum,
                                  size_t * clen, target_t target);
typedef CK_RV (*m_GenerateKeyPair_t) (CK_MECHANISM_PTR pmech,
                                      CK_ATTRIBUTE_PTR ppublic,
                                      CK_ULONG pubattrs,
                                      CK_ATTRIBUTE_PTR pprivate,
                                      CK_ULONG prvattrs,
                                      const unsigned char *pin,
                                      size_t pinlen, unsigned char *key,
                                      size_t * klen,
                                      unsigned char *pubkey,
                                      size_t * pklen, target_t target);
typedef CK_RV (*m_SignInit_t) (unsigned char *state, size_t * slen,
                               CK_MECHANISM_PTR alg,
                               const unsigned char *key, size_t klen,
                               target_t target);
typedef CK_RV (*m_VerifyInit_t) (unsigned char *state, size_t * slen,
                                 CK_MECHANISM_PTR alg,
                                 const unsigned char *key, size_t klen,
                                 target_t target);
typedef CK_RV (*m_SignUpdate_t) (unsigned char *state, size_t slen,
                                 CK_BYTE_PTR data, CK_ULONG dlen,
                                 target_t target);
typedef CK_RV (*m_VerifyUpdate_t) (unsigned char *state, size_t slen,
                                   CK_BYTE_PTR data, CK_ULONG dlen,
                                   target_t target);
typedef CK_RV (*m_SignFinal_t) (const unsigned char *state, size_t stlen,
                                CK_BYTE_PTR sig, CK_ULONG_PTR siglen,
                                target_t target);
typedef CK_RV (*m_VerifyFinal_t) (const unsigned char *state,
                                  size_t stlen, CK_BYTE_PTR sig,
                                  CK_ULONG siglen, target_t target);
typedef CK_RV (*m_Sign_t) (const unsigned char *state, size_t stlen,
                           CK_BYTE_PTR data, CK_ULONG dlen,
                           CK_BYTE_PTR sig, CK_ULONG_PTR siglen,
                            target_t target);
typedef CK_RV (*m_Verify_t) (const unsigned char *state, size_t stlen,
                             CK_BYTE_PTR data, CK_ULONG dlen,
                             CK_BYTE_PTR sig, CK_ULONG siglen,
                             target_t target);
typedef CK_RV (*m_SignSingle_t) (const unsigned char *key, size_t klen,
                                 CK_MECHANISM_PTR pmech,
                                 CK_BYTE_PTR data, CK_ULONG dlen,
                                 CK_BYTE_PTR sig, CK_ULONG_PTR slen,
                                 target_t target);
typedef CK_RV (*m_VerifySingle_t) (const unsigned char *key, size_t klen,
                                   CK_MECHANISM_PTR pmech,
                                   CK_BYTE_PTR data, CK_ULONG dlen,
                                   CK_BYTE_PTR sig, CK_ULONG slen,
                                   target_t target);

/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
typedef CK_RV (*m_WrapKey_t) (const unsigned char *key, size_t keylen,
                              const unsigned char *kek, size_t keklen,
                              const unsigned char *mackey, size_t mklen,
                              const CK_MECHANISM_PTR pmech,
                              CK_BYTE_PTR wrapped, CK_ULONG_PTR wlen,
                               target_t target);
 /**/
/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
typedef CK_RV (*m_UnwrapKey_t) (const CK_BYTE_PTR wrapped, CK_ULONG wlen,
                                const unsigned char *kek, size_t keklen,
                                const unsigned char *mackey,
                                size_t mklen, const unsigned char *pin,
                                size_t pinlen,
                                const CK_MECHANISM_PTR uwmech,
                                const CK_ATTRIBUTE_PTR ptempl,
                                CK_ULONG pcount,
                                unsigned char *unwrapped, size_t * uwlen,
                                CK_BYTE_PTR csum, CK_ULONG * cslen,
                                target_t target);

typedef CK_RV (*m_DeriveKey_t) (CK_MECHANISM_PTR pderivemech,
                                CK_ATTRIBUTE_PTR ptempl,
                                CK_ULONG templcount,
                                const unsigned char *basekey,
                                size_t bklen,
                                const unsigned char *data, size_t dlen,
                                const unsigned char *pin, size_t pinlen,
                                unsigned char *newkey, size_t * nklen,
                                unsigned char *csum, size_t * cslen,
                                target_t target);

typedef CK_RV (*m_GetMechanismList_t) (CK_SLOT_ID slot,
                                       CK_MECHANISM_TYPE_PTR mechs,
                                       CK_ULONG_PTR count,
                                       target_t target);
typedef CK_RV (*m_GetMechanismInfo_t) (CK_SLOT_ID slot,
                                       CK_MECHANISM_TYPE mech,
                                       CK_MECHANISM_INFO_PTR pmechinfo,
                                       target_t target);
typedef CK_RV (*m_GetAttributeValue_t) (const unsigned char *obj,
                                        size_t olen,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulCount,
                                        target_t target);
typedef CK_RV (*m_SetAttributeValue_t) (unsigned char *obj, size_t olen,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_ULONG ulCount,
                                        target_t target);
typedef CK_RV (*m_Login_t) (CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
                            const unsigned char *nonce, size_t nlen,
                            unsigned char *pinblob, size_t * pinbloblen,
                            target_t target);
typedef CK_RV (*m_Logout_t) (const unsigned char *pin, size_t len,
                             target_t target);
typedef CK_RV (*m_LoginExtended_t) (CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
                                    const unsigned char *nonce, size_t nlen,
                                    const unsigned char *xstruct, size_t xslen,
                                    unsigned char *pinblob, size_t *pinbloblen,
                                    target_t target);
typedef CK_RV (*m_LogoutExtended_t) (CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
                                     const unsigned char *nonce, size_t nlen,
                                     const unsigned char *xstruct, size_t xslen,
                                     target_t target);
typedef CK_RV (*m_admin_t) (unsigned char *response1, size_t * r1len,
                            unsigned char *response2, size_t * r2len,
                            const unsigned char *cmd, size_t clen,
                            const unsigned char *sigs, size_t slen,
                            target_t target);
typedef int (*m_add_backend_t) (const char *name, unsigned int port);
typedef int (*m_init_t) (void);
typedef int (*m_shutdown_t) (void);
typedef int (*m_add_module_t) (XCP_Module_t module, target_t *target);
typedef int (*m_rm_module_t) (XCP_Module_t module, target_t target);
typedef CK_RV (*m_get_xcp_info_t)(CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
                                unsigned int query, unsigned int subquery,
                                target_t target);
typedef long (*xcpa_cmdblock_t) (unsigned char *, size_t, unsigned int,
                                 const struct XCPadmresp *,
                                 const unsigned char *,
                                 const unsigned char *, size_t);
typedef long (*xcpa_queryblock_t) (unsigned char *blk, size_t blen,
                                   unsigned int fn, uint64_t domain,
                                   const unsigned char *payload, size_t plen);
typedef long (*xcpa_internal_rv_t) (const unsigned char *, size_t,
                                    struct XCPadmresp *, CK_RV *);



#endif
