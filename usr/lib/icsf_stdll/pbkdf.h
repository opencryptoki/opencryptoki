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

#endif
