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
#define DKEYLEN		32      // 256 bytes is max key size to be derived
#define PIN_SIZE	80	// samedefine in pkcsconf
#define ENCRYPT_SIZE	96	// PIN_SIZE + AES_BLOCK_SIZE (for padding)

#define ICSF_CONFIG_PATH	CONFIG_PATH "/icsf"
#define RACFFILE	ICSF_CONFIG_PATH "/RACF"

CK_RV get_randombytes(char *output, int bytes);

CK_RV encrypt_aes(CK_BYTE *racfpwd, int racflen, CK_BYTE *dkey,
		      CK_BYTE *iv, CK_BYTE *outbuf, int *outbuflen);

CK_RV decrypt_aes(CK_BYTE *edata, int edatalen, CK_BYTE *dkey,
                 CK_BYTE *iv, CK_BYTE *ddata, int *ddatalen);

CK_RV get_racf(CK_BYTE *mk, CK_ULONG mklen, CK_BYTE *racfpwd, int *racflen);

CK_RV get_masterkey(CK_BYTE *pin, CK_ULONG pinlen, CK_BYTE *fname,
			CK_BYTE *mk, int *mklen);

CK_RV pbkdf(CK_BYTE *passwd, CK_ULONG passwdlen, CK_BYTE *salt,
		CK_BYTE *dkey, CK_ULONG klen);

CK_RV secure_racf(CK_BYTE *racfpwd, CK_ULONG racflen, CK_BYTE *mk,
			CK_ULONG mklen);

CK_RV secure_masterkey(CK_BYTE *masterkey, CK_ULONG len, CK_BYTE *pin,
			CK_ULONG pinlen, CK_BYTE *fname);

#endif
