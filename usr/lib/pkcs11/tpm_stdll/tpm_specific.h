/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

#ifndef _TPM_SPECIFIC_H_
#define _TPM_SPECIFIC_H_

#include <openssl/rsa.h>

/* TSS key type helper */
#define TPMTOK_TSS_KEY_TYPE_MASK	0x000000F0
#define TPMTOK_TSS_KEY_TYPE(x)		(x & TPMTOK_TSS_KEY_TYPE_MASK)
#define TPMTOK_TSS_KEY_MIG_TYPE(x)	(x & TSS_KEY_MIGRATABLE)

#define TPMTOK_TSS_MAX_ERROR		0x00000FFF
#define TPMTOK_TSS_ERROR_CODE(x)	(x & TPMTOK_TSS_MAX_ERROR)

/* key types in the TPM token */
#define TPMTOK_PRIVATE_ROOT_KEY	1
#define TPMTOK_PRIVATE_LEAF_KEY	2
#define TPMTOK_PUBLIC_ROOT_KEY	3
#define TPMTOK_PUBLIC_LEAF_KEY	4

/* key identifiers for the PKCS#11 objects */
#define TPMTOK_PRIVATE_ROOT_KEY_ID	"PRIVATE ROOT KEY"
#define TPMTOK_PRIVATE_LEAF_KEY_ID	"PRIVATE LEAF KEY"
#define TPMTOK_PUBLIC_ROOT_KEY_ID	"PUBLIC ROOT KEY"
#define TPMTOK_PUBLIC_LEAF_KEY_ID	"PUBLIC LEAF KEY"

#define TPMTOK_PRIVATE_ROOT_KEY_ID_SIZE	strlen(TPMTOK_PRIVATE_ROOT_KEY_ID)
#define TPMTOK_PRIVATE_LEAF_KEY_ID_SIZE	strlen(TPMTOK_PRIVATE_LEAF_KEY_ID)
#define TPMTOK_PUBLIC_ROOT_KEY_ID_SIZE	strlen(TPMTOK_PUBLIC_ROOT_KEY_ID)
#define TPMTOK_PUBLIC_LEAF_KEY_ID_SIZE	strlen(TPMTOK_PUBLIC_LEAF_KEY_ID)

#define TPMTOK_PUB_ROOT_KEY_FILE	"PUBLIC_ROOT_KEY.pem"
#define TPMTOK_PRIV_ROOT_KEY_FILE	"PRIVATE_ROOT_KEY.pem"

/* TPM token specific return codes */
#define CKR_KEY_NOT_FOUND	CKR_VENDOR_DEFINED + 0x0f000000
#define CKR_FILE_NOT_FOUND	CKR_VENDOR_DEFINED + 0x0f000001

#define TPMTOK_MASTERKEY_PRIVATE	"MK_PRIVATE"

#ifdef DEBUG
#define DEBUG_openssl_print_errors()    openssl_print_errors()
#else
#define DEBUG_openssl_print_errors()
#endif

/* retry count for generating software RSA keys */
#define KEYGEN_RETRY    5

RSA *openssl_gen_key();
int openssl_write_key(RSA *, char *, CK_BYTE *);
CK_RV openssl_read_key(char *, CK_BYTE *, RSA **);
int openssl_get_modulus_and_prime(RSA *, unsigned int *, unsigned char *, unsigned int *, unsigned char *);
int util_set_file_mode(char *, mode_t);
CK_BYTE *util_create_id(int);
CK_RV util_set_username(char **);
unsigned int util_get_keysize_flag(CK_ULONG);
CK_ULONG util_check_public_exponent(TEMPLATE *);

#define NULL_HKEY	0
#define NULL_HENCDATA	0
#define NULL_HPOLICY	0
#define NULL_HCONTEXT	0
#define NULL_HPCRS	0

/* CKA_ENC_AUTHDATA will be used to store the encrypted SHA-1 hashes of auth data
 * passed in for TPM keys. The authdata will be encrypted using either the public
 * leaf key or the private leaf key */
#define CKA_ENC_AUTHDATA        CKA_VENDOR_DEFINED + 0x01000001

#define MK_SIZE (AES_KEY_SIZE_256)

struct srk_info
{
	char *secret;
	int mode;
	int len;
};

int get_srk_info(struct srk_info *srk);

#endif
