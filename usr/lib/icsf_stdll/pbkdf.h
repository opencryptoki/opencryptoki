/*
 * COPYRIGHT (c) International Business Machines Corp. 2012-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * OpenCryptoki ICSF token - LDAP functions
 *
 * Author: Joy Latten (jmlatten@linux.vnet.ibm.com)
 *
 */

#ifndef PBKDF_H
#define PBKDF_H

#define SALTSIZE        16      // salt is 16 bytes
#define DKEYLEN  32      // 256 bytes is max key size to be derived
#define PIN_SIZE 80      // same define in pkcsconf
#define ENCRYPT_SIZE 96      // PIN_SIZE + AES_BLOCK_SIZE (for padding)

/*
 * SP 800-132 recommends a minimum iteration count of 1000.
 * so lets try that for now...
 */
#define ITERATIONS 1000

#define RACFFILE            "RACF"

#define ICSF_MK_FILE_VERSION    2

/*
 * Version 3 master key file format (tokversion >= 3.28):
 *   u8   wrapped[40]  = AES-256-KW (RFC 3394) of the 32-byte master key
 *                       under the PBKDF2-SHA-512 wrap key stored in
 *                       TOKEN_DATA_VERSION.{so,user}_wrap_key.
 *
 * No version field - identical layout to loadsave.c save_masterkey_so/user.
 * File size (40 bytes) is the implicit format discriminator.
 */
/* Size of an AES-256-KW output for a 32-byte plaintext (RFC 3394) */
#define ICSF_MK_FILE_V3_SIZE    40

/*
 * Version 3 RACF file format (tokversion >= 3.28):
 *   u32  version         = ICSF_RACF_FILE_VERSION_3
 *   u8   iv[12]          random GCM nonce
 *   u8   tag[16]         GCM authentication tag
 *   u32  ciphertext_len  length of the encrypted RACF password
 *   u8   ciphertext[...]
 *
 * The 32-byte AES master key is used directly as the GCM key.
 * The token name (tokname) is passed as AAD.
 */
#define ICSF_RACF_FILE_VERSION_3    3

CK_RV get_randombytes(unsigned char *output, int bytes);

CK_RV encrypt_aes(STDLL_TokData_t *tokdata,
                  CK_BYTE * racfpwd, int racflen, CK_BYTE * dkey,
                  CK_BYTE * iv, CK_BYTE * outbuf, int *outbuflen,
                  CK_BBOOL wrap);

CK_RV decrypt_aes(STDLL_TokData_t *tokdata,
                  CK_BYTE * edata, int edatalen, CK_BYTE * dkey,
                  CK_BYTE * iv, CK_BYTE * ddata, int *ddatalen,
                  CK_BBOOL unwrap);

CK_RV get_racf(STDLL_TokData_t *tokdata,
               CK_BYTE * mk, CK_ULONG mklen, CK_BYTE * racfpwd, int *racflen);

CK_RV get_masterkey(STDLL_TokData_t *tokdata,
                    CK_BYTE *pin, CK_ULONG pinlen, const char *fname,
                    CK_BYTE *masterkey, int *len);

CK_RV pbkdf_old(STDLL_TokData_t *tokdata,
                CK_BYTE * passwd, CK_ULONG passwdlen, CK_BYTE * salt,
                CK_BYTE * dkey, CK_ULONG klen);

CK_RV pbkdf_openssl(STDLL_TokData_t *tokdata,
                    CK_BYTE *password, CK_ULONG len, CK_BYTE *salt,
                    CK_BYTE *dkey, CK_ULONG klen);

CK_RV secure_racf(STDLL_TokData_t *tokdata,
                  CK_BYTE * racfpwd, CK_ULONG racflen, CK_BYTE * mk,
                  CK_ULONG mklen, const char *tokname);

CK_RV secure_masterkey(STDLL_TokData_t *tokdata,
                       CK_BYTE * masterkey, CK_ULONG len, CK_BYTE * pin,
                       CK_ULONG pinlen, const char *fname);

/*
 * New-format (v3) master key helpers - used when tokversion >= 3.28.
 * The wrap key is the caller's PBKDF2-derived so_wrap_key / user_wrap_key
 * from TOKEN_DATA_VERSION (32 bytes).
 */
CK_RV secure_masterkey_v3(STDLL_TokData_t *tokdata,
                           const CK_BYTE *masterkey,
                           const CK_BYTE wrap_key[32],
                           const char *fname);

CK_RV get_masterkey_v3(STDLL_TokData_t *tokdata,
                       const CK_BYTE wrap_key[32],
                       const char *fname,
                       CK_BYTE masterkey[32]);

/*
 * New-format (v3) RACF file helpers - used when tokversion >= 3.28.
 * The master key (32 bytes) is used directly as the AES-256-GCM key.
 * The token name string is passed as AAD.
 */
CK_RV secure_racf_v3(STDLL_TokData_t *tokdata,
                     const CK_BYTE *racf, CK_ULONG racflen,
                     const CK_BYTE masterkey[32],
                     const char *tokname);

CK_RV get_racf_v3(STDLL_TokData_t *tokdata,
                  const CK_BYTE masterkey[32],
                  CK_BYTE *racfpwd, int *racflen);

#endif
