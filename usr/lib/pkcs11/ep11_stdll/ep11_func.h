/*
 * COPYRIGHT (c) International Business Machines Corp. 2016-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

typedef unsigned int (*m_GenerateRandom_t)(CK_BYTE_PTR rnd, CK_ULONG len,
					   uint64_t target);
typedef unsigned int (*m_SeedRandom_t)(CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen,
				       uint64_t target);
typedef unsigned int (*m_Digest_t)(const unsigned char *state, size_t slen,
				   CK_BYTE_PTR data, CK_ULONG len,
				   CK_BYTE_PTR digest, CK_ULONG_PTR dglen,
				   uint64_t target);
typedef unsigned int (*m_DigestInit_t)(unsigned char *state, size_t *len,
				       const CK_MECHANISM_PTR pmech,
				       uint64_t target);
typedef unsigned int (*m_DigestUpdate_t)(unsigned char *state, size_t slen,
					 CK_BYTE_PTR data, CK_ULONG dlen,
					 uint64_t target);
typedef unsigned int (*m_DigestKey_t)(unsigned char *state, size_t slen,
				      const unsigned char *key, size_t klen,
				      uint64_t target);
typedef unsigned int (*m_DigestFinal_t)(const unsigned char *state, size_t slen,
					CK_BYTE_PTR digest, CK_ULONG_PTR dlen,
					uint64_t target);
typedef unsigned int (*m_DigestSingle_t)(CK_MECHANISM_PTR pmech,
					 CK_BYTE_PTR data, CK_ULONG len,
					 CK_BYTE_PTR digest, CK_ULONG_PTR dlen,
				       uint64_t target);
typedef unsigned int (*m_EncryptInit_t)(unsigned char *state, size_t *slen,
					CK_MECHANISM_PTR pmech,
					const unsigned char *key,   size_t klen,
					uint64_t target);
typedef unsigned int (*m_DecryptInit_t)(unsigned char *state, size_t *slen,
					CK_MECHANISM_PTR pmech,
					const unsigned char *key, size_t klen,
					uint64_t target);
typedef unsigned int (*m_EncryptUpdate_t)(unsigned char *state, size_t slen,
					  CK_BYTE_PTR plain, CK_ULONG plen,
					  CK_BYTE_PTR cipher, CK_ULONG_PTR clen,
					  uint64_t target);
typedef unsigned int (*m_DecryptUpdate_t)(unsigned char *state, size_t slen,
					  CK_BYTE_PTR cipher, CK_ULONG clen,
					  CK_BYTE_PTR plain, CK_ULONG_PTR plen,
					  uint64_t target);
typedef unsigned int (*m_Encrypt_t)(const unsigned char *state, size_t slen,
				    CK_BYTE_PTR plain, CK_ULONG plen,
				    CK_BYTE_PTR cipher, CK_ULONG_PTR clen,
				    uint64_t target);
typedef unsigned int (*m_Decrypt_t)(const unsigned char *state, size_t slen,
				    CK_BYTE_PTR cipher, CK_ULONG clen,
				    CK_BYTE_PTR plain,  CK_ULONG_PTR plen,
				    uint64_t target);
typedef unsigned int (*m_EncryptFinal_t)(const unsigned char *state,
					 size_t slen, CK_BYTE_PTR output,
					 CK_ULONG_PTR len, uint64_t target);
typedef unsigned int (*m_DecryptFinal_t)(const unsigned char *state,
					 size_t slen, CK_BYTE_PTR output,
					 CK_ULONG_PTR len, uint64_t target);
typedef unsigned int (*m_EncryptSingle_t)(const unsigned char *key, size_t klen,
					  CK_MECHANISM_PTR mech,
					  CK_BYTE_PTR plain, CK_ULONG plen,
					  CK_BYTE_PTR cipher, CK_ULONG_PTR clen,
					  uint64_t target);
typedef unsigned int (*m_DecryptSingle_t)(const unsigned char *key, size_t klen,
					  CK_MECHANISM_PTR mech,
					  CK_BYTE_PTR cipher, CK_ULONG clen,
					  CK_BYTE_PTR plain, CK_ULONG_PTR plen,
					  uint64_t target);
typedef unsigned int (*m_ReencryptSingle_t)(const unsigned char *dkey,
					    size_t dklen,
					    const unsigned char *ekey,
					    size_t eklen,
					    CK_MECHANISM_PTR pdecrmech,
					    CK_MECHANISM_PTR pencrmech,
					    CK_BYTE_PTR in, CK_ULONG ilen,
					    CK_BYTE_PTR out, CK_ULONG_PTR olen,
					    uint64_t target) ;
typedef unsigned int (*m_GenerateKey_t)(CK_MECHANISM_PTR pmech,
					CK_ATTRIBUTE_PTR ptempl,
					CK_ULONG templcount,
					const unsigned char *pin, size_t pinlen,
					unsigned char *key,     size_t *klen,
					unsigned char *csum,    size_t *clen,
					uint64_t target) ;
typedef unsigned int (*m_GenerateKeyPair_t)(CK_MECHANISM_PTR pmech,
					    CK_ATTRIBUTE_PTR ppublic,
					    CK_ULONG pubattrs,
					    CK_ATTRIBUTE_PTR pprivate,
					    CK_ULONG prvattrs,
					    const unsigned char *pin,
					    size_t pinlen, unsigned char *key,
					    size_t *klen, unsigned char *pubkey,
					    size_t *pklen, uint64_t target);
typedef unsigned int (*m_SignInit_t)(unsigned char *state, size_t *slen,
				     CK_MECHANISM_PTR alg,
				     const unsigned char *key, size_t klen,
				     uint64_t target);
typedef unsigned int (*m_VerifyInit_t)(unsigned char *state, size_t *slen,
				       CK_MECHANISM_PTR alg,
				       const unsigned char *key, size_t klen,
				       uint64_t target);
typedef unsigned int (*m_SignUpdate_t)(unsigned char *state, size_t slen,
				       CK_BYTE_PTR data, CK_ULONG dlen,
				       uint64_t target);
typedef unsigned int (*m_VerifyUpdate_t)(unsigned char *state, size_t slen,
					 CK_BYTE_PTR data, CK_ULONG dlen,
					 uint64_t target);
typedef unsigned int (*m_SignFinal_t)(const unsigned char *state, size_t stlen,
				      CK_BYTE_PTR sig,   CK_ULONG_PTR siglen,
				      uint64_t target);
typedef unsigned int (*m_VerifyFinal_t)(const unsigned char *state, size_t stlen,
					CK_BYTE_PTR sig, CK_ULONG siglen,
					uint64_t target);
typedef unsigned int (*m_Sign_t)(const unsigned char *state, size_t stlen,
				 CK_BYTE_PTR data, CK_ULONG dlen,
				 CK_BYTE_PTR sig, CK_ULONG_PTR siglen,
				 uint64_t target);
typedef unsigned int (*m_Verify_t)(const unsigned char *state, size_t stlen,
				   CK_BYTE_PTR data, CK_ULONG dlen,
				   CK_BYTE_PTR sig, CK_ULONG siglen,
				   uint64_t target);
typedef unsigned int (*m_SignSingle_t)(const unsigned char *key, size_t klen,
				       CK_MECHANISM_PTR pmech,
				       CK_BYTE_PTR data, CK_ULONG dlen,
				       CK_BYTE_PTR sig, CK_ULONG_PTR slen,
				       uint64_t target);
typedef unsigned int (*m_VerifySingle_t)(const unsigned char *key, size_t klen,
					 CK_MECHANISM_PTR pmech,
					 CK_BYTE_PTR data, CK_ULONG dlen,
					 CK_BYTE_PTR sig, CK_ULONG slen,
					 uint64_t target);

/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
typedef unsigned int (*m_WrapKey_t)(const unsigned char *key, size_t keylen,
				    const unsigned char *kek, size_t keklen,
				    const unsigned char *mackey, size_t mklen,
				    const CK_MECHANISM_PTR pmech,
				    CK_BYTE_PTR wrapped, CK_ULONG_PTR wlen,
				    uint64_t target);
/**/
/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
typedef unsigned int (*m_UnwrapKey_t)(const CK_BYTE_PTR wrapped, CK_ULONG wlen,
				      const unsigned char *kek, size_t keklen,
				      const unsigned char *mackey, size_t mklen,
				      const unsigned char *pin, size_t pinlen,
				      const CK_MECHANISM_PTR uwmech,
				      const CK_ATTRIBUTE_PTR ptempl,
				      CK_ULONG pcount, unsigned char *unwrapped,
				      size_t *uwlen, CK_BYTE_PTR csum,
				      CK_ULONG *cslen, uint64_t target);

typedef unsigned int (*m_DeriveKey_t)(CK_MECHANISM_PTR pderivemech,
				      CK_ATTRIBUTE_PTR ptempl,
				      CK_ULONG templcount,
				      const unsigned char *basekey,
				      size_t bklen,
				      const unsigned char *data, size_t dlen,
				      const unsigned char *pin, size_t pinlen,
				      unsigned char *newkey, size_t *nklen,
				      unsigned char *csum, size_t *cslen,
				      uint64_t target);

typedef unsigned int (*m_GetMechanismList_t)(CK_SLOT_ID slot,
					     CK_MECHANISM_TYPE_PTR mechs,
					     CK_ULONG_PTR count,
					     uint64_t target);
typedef unsigned int (*m_GetMechanismInfo_t)(CK_SLOT_ID slot,
					     CK_MECHANISM_TYPE mech,
					     CK_MECHANISM_INFO_PTR pmechinfo,
					     uint64_t target) ;
typedef unsigned int (*m_GetAttributeValue_t)(const unsigned char *obj,
					      size_t olen,
					      CK_ATTRIBUTE_PTR pTemplate,
					      CK_ULONG ulCount,
					      uint64_t target) ;
typedef unsigned int (*m_SetAttributeValue_t)(unsigned char *obj, size_t olen,
					      CK_ATTRIBUTE_PTR pTemplate,
					      CK_ULONG ulCount,
					      uint64_t target) ;
typedef unsigned int (*m_Login_t)(CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
				  const unsigned char *nonce, size_t nlen,
				  unsigned char *pinblob, size_t *pinbloblen,
				  uint64_t target);
typedef unsigned int (*m_Logout_t)(const unsigned char *pin, size_t len,
				   uint64_t target);
typedef unsigned int (*m_admin_t)(unsigned char *response1, size_t *r1len,
				  unsigned char *response2, size_t *r2len,
				  const unsigned char *cmd, size_t clen,
				  const unsigned char *sigs, size_t slen,
				  uint64_t target);
typedef unsigned int (*m_add_backend_t)(const char *name, unsigned int port);
typedef unsigned int (*m_init_t)(void);
typedef unsigned int (*m_shutdown_t)(void);
