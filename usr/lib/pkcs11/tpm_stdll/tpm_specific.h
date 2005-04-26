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

/* for use in the token object storage paths, etc */
#define TPMTOK_TOKEN_NAME	tpm

/* locations to write the backup copies of the sw generated keys */
#define TPMTOK_PUBLIC_ROOT_KEY_LOCATION		"/etc/pkcs11/tpm/PUBLIC_ROOT_KEY.pem"
#define TPMTOK_PRIVATE_ROOT_KEY_LOCATION	"/etc/pkcs11/tpm/PRIVATE_ROOT_KEY.pem"

/* TPM token specific return codes */
#define CKR_KEY_NOT_FOUND	CKR_VENDOR_DEFINED + 0
#define CKR_DATA_OBJ_NOT_FOUND	CKR_VENDOR_DEFINED + 1

#define TPMTOK_MASTERKEY_PUBLIC		"MK_PUBLIC"
#define TPMTOK_MASTERKEY_PRIVATE	"MK_PRIVATE"

RSA *openssl_gen_key();
int openssl_write_key(RSA *, char *, char *);
CK_RV openssl_read_key(char *, char *, RSA **);
int openssl_get_modulus_and_prime(RSA *, unsigned int *, unsigned char *, unsigned int *, unsigned char *);
int util_set_file_mode(char *, mode_t);
char *util_create_id(int);
CK_RV util_set_username(char **);
unsigned int util_get_keysize_flag(CK_ULONG);

#endif
