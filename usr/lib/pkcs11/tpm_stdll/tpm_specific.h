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
#define TPMTOK_ROOT_KEY		0
#define TPMTOK_MIG_ROOT_KEY	1
#define TPMTOK_MIG_LEAF_KEY	2
#define TPMTOK_USER_BASE_KEY	3
#define TPMTOK_USER_LEAF_KEY	4
#define TPMTOK_USER_KEY		5
#define TPMTOK_SO_KEY		6
#define TPMTOK_PUB_ROOT_KEY	7

/* key identifier suffixes for the PKCS#11 objects */
#define TPMTOK_ROOT_KEY_ID	"00 TPM 00 ROOT KEY"
#define TPMTOK_MIG_ROOT_KEY_ID	"MIG ROOT KEY"
#define TPMTOK_MIG_LEAF_KEY_ID	"MIG LEAF KEY"
#define TPMTOK_USER_BASE_KEY_ID	"BASE KEY"
#define TPMTOK_USER_LEAF_KEY_ID	"LEAF KEY"
#define TPMTOK_PUB_ROOT_KEY_ID	"PUB ROOT KEY"

/* for use in the token object storage paths, etc */
#define TPMTOK_TOKEN_NAME	tpm

/* locations to write the backup copies of the sw generated keys */
#define TPMTOK_ROOT_KEY_BACKUP_LOCATION		"/etc/pkcs11/tpm/ROOT_KEY.pem"
#define TPMTOK_MIG_ROOT_KEY_BACKUP_LOCATION	"/etc/pkcs11/tpm/MIG_ROOT_KEY.pem"
#define TPMTOK_PUB_ROOT_KEY_BACKUP_LOCATION	"/etc/pkcs11/tpm/PUB_ROOT_KEY.pem"
#define TPMTOK_USER_BASE_KEY_BACKUP_LOCATION	"/etc/pkcs11/tpm/TOK_OBJ/%s/%s_BASE_KEY.pem"

#if 0
/* Application ID for objects created by this token */
#define TPMTOK_APPLICATION_ID	"PKCS#11 TPM Token"
#endif

#define TPMTOK_ROOT_KEY_ID_SIZE		strlen(TPMTOK_ROOT_KEY_ID)
#define TPMTOK_MIG_ROOT_KEY_ID_SIZE	strlen(TPMTOK_MIG_ROOT_KEY_ID)
#define TPMTOK_MIG_LEAF_KEY_ID_SIZE	strlen(TPMTOK_MIG_LEAF_KEY_ID)
#define TPMTOK_USER_BASE_KEY_ID_SIZE	strlen(TPMTOK_USER_BASE_KEY_ID)
#define TPMTOK_USER_LEAF_KEY_ID_SIZE	strlen(TPMTOK_USER_LEAF_KEY_ID)
#define TPMTOK_PUB_ROOT_KEY_ID_SIZE	strlen(TPMTOK_PUB_ROOT_KEY_ID)

/* TPM token specific return codes */
#define CKR_KEY_NOT_FOUND	CKR_VENDOR_DEFINED + 0
#define CKR_DATA_OBJ_NOT_FOUND	CKR_VENDOR_DEFINED + 1

RSA *openssl_gen_key();
int openssl_write_key(RSA *, char *, char *);
CK_RV openssl_read_key(char *, char *, RSA **);
int openssl_get_modulus_and_prime(RSA *, unsigned int *, unsigned char *, unsigned int *, unsigned char *);
int util_create_user_dir(char *);
int util_set_file_mode(char *, mode_t);
char *util_create_id(int);
CK_RV util_set_username(char **);
#endif
