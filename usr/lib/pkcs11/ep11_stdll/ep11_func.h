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

#ifndef XCP_SERIALNR_CHARS
    #define XCP_SERIALNR_CHARS        8
#endif
#ifndef XCP_ADMCTR_BYTES
    #define XCP_ADMCTR_BYTES          ((size_t) (128/8))
#endif
#ifndef XCP_ADM_QUERY
    #define XCP_ADM_QUERY              0x10000
#endif
#ifndef XCP_ADMQ_DOM_CTRLPOINTS
    #define XCP_ADMQ_DOM_CTRLPOINTS    6 | XCP_ADM_QUERY // domain CP
#endif

#ifndef __xcpadm_h__
typedef struct XCPadmresp {
    uint32_t fn;
    uint32_t domain;
    uint32_t domainInst;

    /* module ID || module instance */
    unsigned char module[ XCP_SERIALNR_CHARS + XCP_SERIALNR_CHARS ];
    unsigned char   modNr[ XCP_SERIALNR_CHARS ];
    unsigned char modInst[ XCP_SERIALNR_CHARS ];

    unsigned char   tctr[ XCP_ADMCTR_BYTES ];     /* transaction counter */

    CK_RV rv;
    uint32_t reason;

    // points to original response; NULL if no payload
    // make sure it's copied if used after releasing response block
    //
    const unsigned char *payload;
    size_t pllen;
} *XCPadmresp_t;
#endif

#ifndef XCP_CPB_ADD_CPBS
    #define XCP_CPB_ADD_CPBS            0   // allow addition (activation) of CP bits
    #define XCP_CPB_DELETE_CPBS         1   // allow removal (deactivation) of CP bits
                                            // remove both ADD_CPBs and DELETE_CPBs
                                            // to make unit read-only
    #define XCP_CPB_SIGN_ASYMM          2   // sign with private keys
    #define XCP_CPB_SIGN_SYMM           3   // sign with HMAC or CMAC
    #define XCP_CPB_SIGVERIFY_SYMM      4   // verify with HMAC or CMAC
    #define XCP_CPB_ENCRYPT_SYMM        5   // encrypt with symmetric keys
                                            // No asymmetric counterpart: one
                                            // may not restrict use of public keys
    #define XCP_CPB_DECRYPT_ASYMM       6   // decrypt with private keys
    #define XCP_CPB_DECRYPT_SYMM        7   // decrypt with symmetric keys
    #define XCP_CPB_WRAP_ASYMM          8   // key export with public keys
    #define XCP_CPB_WRAP_SYMM           9   // key export with symmetric keys
    #define XCP_CPB_UNWRAP_ASYMM        10  // key import with private keys
    #define XCP_CPB_UNWRAP_SYMM         11  // key import with symmetric keys
    #define XCP_CPB_KEYGEN_ASYMM        12  // generate asymmetric keypairs
    #define XCP_CPB_KEYGEN_SYMM         13  // generate or derive symmetric keys
                                            // including DSA parameters
    #define XCP_CPB_RETAINKEYS          14  // allow backend to save semi/retained keys
    #define XCP_CPB_SKIP_KEYTESTS       15  // disable selftests on new asymmetric keys
    #define XCP_CPB_NON_ATTRBOUND       16  // allow keywrap without attribute-binding
    #define XCP_CPB_MODIFY_OBJECTS      17  // allow changes to objects (Booleans only)
    #define XCP_CPB_RNG_SEED            18  // allow mixing external seed to RNG
    #define XCP_CPB_ALG_RAW_RSA         19  // allow RSA private-key use without padding
                                            // (highly discouraged)
    #define XCP_CPB_ALG_NFIPS2009       20  // allow non-FIPS-approved algs (as of 2009)
                                            // including non-FIPS keysizes
    #define XCP_CPB_ALG_NBSI2009        21  // allow non-BSI algorithms (as of 2009)
                                            // including non-FIPS keysizes
    #define XCP_CPB_KEYSZ_HMAC_ANY      22  // don't enforce minimum keysize on HMAC
    #define XCP_CPB_KEYSZ_BELOW80BIT    23  // allow algorithms below 80-bit strength
                                            // public-key operations are still allowed
    #define XCP_CPB_KEYSZ_80BIT         24  // allow 80 to 111-bit algorithms
    #define XCP_CPB_KEYSZ_112BIT        25  // allow 112 to 127-bit algorithms
    #define XCP_CPB_KEYSZ_128BIT        26  // allow 128 to 191-bit algorithms
    #define XCP_CPB_KEYSZ_192BIT        27  // allow 192 to 255-bit algorithms
    #define XCP_CPB_KEYSZ_256BIT        28  // allow 256-bit algorithms
    #define XCP_CPB_KEYSZ_RSA65536      29  // allow RSA public exponents below 0x10001
    #define XCP_CPB_ALG_RSA             30  // RSA private-key or key-encrypt use
    #define XCP_CPB_ALG_DSA             31  // DSA private-key use
    #define XCP_CPB_ALG_EC              32  // EC private-key use, see also
                                            // curve restrictions
    #define XCP_CPB_ALG_EC_BPOOLCRV     33  // Brainpool (E.U.) EC curves
    #define XCP_CPB_ALG_EC_NISTCRV      34  // NIST/SECG EC curves
    #define XCP_CPB_ALG_NFIPS2011       35  // allow non-FIPS-approved algs (as of 2011)
                                            // including non-FIPS keysizes
    #define XCP_CPB_ALG_NBSI2011        36  // allow non-BSI algorithms (as of 2011)
                                            // including non-BSI keysizes
    #define XCP_CPB_USER_SET_TRUSTED    37  // allow non-admins to set TRUSTED on a blob/SPKI
    #define XCP_CPB_ALG_SKIP_CROSSCHK   38  // do not double-check sign/decrypt ops
    #define XCP_CPB_WRAP_CRYPT_KEYS     39  // allow keys which can en/decrypt data
                                            // and also un/wrap other keys
    #define XCP_CPB_SIGN_CRYPT_KEYS     40  // allow keys which can en/decrypt data
                                            // and also sign/verify
    #define XCP_CPB_WRAP_SIGN_KEYS      41  // allow keys which can un/wrap data
                                            // and also sign/verify
    #define XCP_CPB_USER_SET_ATTRBOUND  42  // allow non-administrators to
                                            // Wire format 69/82
                                            // mark public key objects ATTRBOUND
    #define XCP_CPB_ALLOW_PASSPHRASE    43  // allow host to pass passprases, such as
                                            // PKCS12 data, in the clear
    #define XCP_CPB_WRAP_STRONGER_KEY   44  // allow wrapping of stronger keys
                                            // by weaker keys
    #define XCP_CPB_WRAP_WITH_RAW_SPKI  45  // allow wrapping with SPKIs without
                                            // MAC and attributes
    #define XCP_CPB_ALG_DH              46  // Diffie-Hellman use (private keys)
    #define XCP_CPB_DERIVE              47  // allow key derivation (symmetric+EC/DH)

    #define XCP_CPBITS_MAX              XCP_CPB_DERIVE // marks last used CPB

    #define  XCP_CPBLOCK_BITS           128 // handle CPs in this granularity
    #define  XCP_CPCOUNT                \
        (((XCP_CPBITS_MAX + XCP_CPBLOCK_BITS-1) / XCP_CPBLOCK_BITS) * XCP_CPBLOCK_BITS)
    #define  XCP_CP_BYTES               (XCP_CPCOUNT / 8)    // full blocks, incl. unused bits

#endif

typedef long (*xcpa_queryblock_t)(unsigned char *blk, size_t blen, unsigned int fn,
                                  uint64_t domain, const unsigned char *payload, size_t plen);
typedef long (*xcpa_internal_rv_t)(const unsigned char *rsp,   size_t rlen,
                                   struct XCPadmresp *rspblk, CK_RV *rv);

