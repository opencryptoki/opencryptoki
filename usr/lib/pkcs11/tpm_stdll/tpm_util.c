
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <openssl/rsa.h>

#include <tss/platform.h>
#include <tss/tcpa_defines.h>
#include <tss/tcpa_typedef.h>
#include <tss/tcpa_struct.h>
#include <tss/tcpa_error.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <trousers/trousers.h>

#include "pkcs11/pkcs11types.h"
#include "pkcs11/stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "../common/args.h"
#include "h_extern.h"

#include "tpm_specific.h"

#ifndef UINT64
#define UINT64 unsigned long long
#endif

extern TSS_HCONTEXT tspContext;

UINT32
util_get_keysize_flag(CK_ULONG size)
{
	switch (size) {
		case 512:
			return TSS_KEY_SIZE_512;
			break;
		case 1024:
			return TSS_KEY_SIZE_1024;
			break;
		case 2048:
			return TSS_KEY_SIZE_2048;
			break;
		default:
			break;
	}

	return 0;
}

CK_BYTE *
util_create_id(int type)
{
	CK_BYTE *ret = NULL;
	int size = 0;

	switch (type) {
		case TPMTOK_PRIVATE_ROOT_KEY:
			size = TPMTOK_PRIVATE_ROOT_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				OCK_LOG_DEBUG("malloc of %d bytes failed.",
						size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PRIVATE_ROOT_KEY_ID);
			break;
		case TPMTOK_PUBLIC_ROOT_KEY:
			size = TPMTOK_PUBLIC_ROOT_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				OCK_LOG_DEBUG("malloc of %d bytes failed.",
						size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PUBLIC_ROOT_KEY_ID);
			break;
		case TPMTOK_PUBLIC_LEAF_KEY:
			size = TPMTOK_PUBLIC_LEAF_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				OCK_LOG_DEBUG("malloc of %d bytes failed.",
						size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PUBLIC_LEAF_KEY_ID);
			break;
		case TPMTOK_PRIVATE_LEAF_KEY:
			size = TPMTOK_PRIVATE_LEAF_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				OCK_LOG_DEBUG("malloc of %d bytes failed.",
						size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PRIVATE_LEAF_KEY_ID);
			break;
		default:
			OCK_LOG_DEBUG("Unknown type passed to %s: %d", __FUNCTION__, type);
			break;
	}

	return ret;
}

int
util_set_file_mode(char *filename, mode_t mode)
{
	struct stat file_stat;

	if (stat(filename, &file_stat) == -1) {
		OCK_LOG_DEBUG("%s: stat: %s", __FUNCTION__, strerror(errno));
		return -1;
	} else if ((file_stat.st_mode ^ mode) != 0) {
		if (chmod(filename, mode) == -1) {
			OCK_LOG_DEBUG("chmod(%s) failed: %s", filename, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/* make sure the public exponent attribute is 65537 */
CK_ULONG
util_check_public_exponent(TEMPLATE *tmpl)
{
	CK_BBOOL flag;
	CK_ATTRIBUTE *publ_exp_attr;
	CK_BYTE pubexp_bytes[] = { 1, 0, 1 };
	CK_ULONG publ_exp, rc = 1;

	flag = template_attribute_find(tmpl, CKA_PUBLIC_EXPONENT, &publ_exp_attr);
	if (!flag){
		OCK_LOG_DEBUG("Couldn't find public exponent attribute");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	switch (publ_exp_attr->ulValueLen) {
		case 3:
			rc = memcmp(pubexp_bytes, publ_exp_attr->pValue, 3);
			break;
		case sizeof(CK_ULONG):
			publ_exp = *((CK_ULONG *)publ_exp_attr->pValue);
			if (publ_exp == 65537)
				rc = 0;
			break;
		default:
			break;
	}

	return rc;
}

TSS_RESULT
util_set_public_modulus(TSS_HKEY hKey, unsigned long size_n, unsigned char *n)
{
	UINT64 offset;
	UINT32 blob_size;
	BYTE *blob, pub_blob[1024];
	TCPA_PUBKEY pub_key;
	TSS_RESULT result;

	/* Get the TCPA_PUBKEY blob from the key object. */
	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				    &blob_size, &blob);
	if (result != TSS_SUCCESS) {
		OCK_LOG_DEBUG("Tspi_GetAttribData failed: rc=0x%x", result);
		return result;
	}

	offset = 0;
	result = Trspi_UnloadBlob_PUBKEY(&offset, blob, &pub_key);
	if (result != TSS_SUCCESS) {
		OCK_LOG_DEBUG("Tspi_GetAttribData failed: rc=0x%x", result);
		return result;
	}

	Tspi_Context_FreeMemory(tspContext, blob);
	/* Free the first dangling reference, putting 'n' in its place */
	free(pub_key.pubKey.key);
	pub_key.pubKey.keyLength = size_n;
	pub_key.pubKey.key = n;

	offset = 0;
	Trspi_LoadBlob_PUBKEY(&offset, pub_blob, &pub_key);

	/* Free the second dangling reference */
	free(pub_key.algorithmParms.parms);

	/* set the public key data in the TSS object */
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				    (UINT32)offset, pub_blob);
	if (result != TSS_SUCCESS) {
		OCK_LOG_DEBUG("Tspi_SetAttribData failed: rc=0x%x", result);
		return result;
	}

	return TSS_SUCCESS;
}

