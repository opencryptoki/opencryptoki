
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
#include "h_extern.h"
#include "trace.h"

#include "tpm_specific.h"

extern TSS_HCONTEXT tspContext;

static struct {
        TSS_FLAG mode;
        const char *str;
} tss_modes[] = {
	{TSS_SECRET_MODE_NONE, "TSS_SECRET_MODE_NONE"},
	{TSS_SECRET_MODE_SHA1, "TSS_SECRET_MODE_SHA1"},
	{TSS_SECRET_MODE_PLAIN,"TSS_SECRET_MODE_PLAIN"},
	{TSS_SECRET_MODE_POPUP, "TSS_SECRET_MODE_POPUP"},
	{TSS_SECRET_MODE_CALLBACK, "TSS_SECRET_MODE_CALLBACK"},
};

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
				TRACE_ERROR("malloc of %d bytes failed.", size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PRIVATE_ROOT_KEY_ID);
			break;
		case TPMTOK_PUBLIC_ROOT_KEY:
			size = TPMTOK_PUBLIC_ROOT_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				TRACE_ERROR("malloc of %d bytes failed.", size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PUBLIC_ROOT_KEY_ID);
			break;
		case TPMTOK_PUBLIC_LEAF_KEY:
			size = TPMTOK_PUBLIC_LEAF_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				TRACE_ERROR("malloc of %d bytes failed.", size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PUBLIC_LEAF_KEY_ID);
			break;
		case TPMTOK_PRIVATE_LEAF_KEY:
			size = TPMTOK_PRIVATE_LEAF_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				TRACE_ERROR("malloc of %d bytes failed.", size);
				break;
			}

			sprintf((char *)ret, "%s", TPMTOK_PRIVATE_LEAF_KEY_ID);
			break;
		default:
			TRACE_ERROR("Unknown type: %d\n", type);
			break;
	}

	return ret;
}

int
util_set_file_mode(char *filename, mode_t mode)
{
	struct stat file_stat;

	if (stat(filename, &file_stat) == -1) {
		TRACE_ERROR("stat failed: %s\n", strerror(errno));
		return -1;
	} else if ((file_stat.st_mode ^ mode) != 0) {
		if (chmod(filename, mode) == -1) {
			TRACE_ERROR("chmod(%s) failed: %s\n", filename,
				     strerror(errno));
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
		TRACE_ERROR("Couldn't find public exponent attribute.\n");
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
		TRACE_ERROR("Tspi_GetAttribData failed: rc=0x%x", result);
		return result;
	}

	offset = 0;
	result = Trspi_UnloadBlob_PUBKEY(&offset, blob, &pub_key);
	if (result != TSS_SUCCESS) {
		TRACE_ERROR("Tspi_GetAttribData failed: rc=0x%x", result);
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
		TRACE_ERROR("Tspi_SetAttribData failed: rc=0x%x", result);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_FLAG
get_srk_mode(void)
{
	char *mode = NULL;
	int i;
	int num_modes = sizeof(tss_modes)/sizeof(tss_modes[0]);
	
	mode = getenv("OCK_SRK_MODE");
	if (mode == NULL)
		return 0;

	/* parse */
	for (i = 0; i < num_modes; i++) {
		if (strncmp(mode, tss_modes[i].str, strlen(mode)) == 0)
			return tss_modes[i].mode;
	}

	TRACE_ERROR("Unknown TSS mode set in OCK_SRK_MODE, %s.\n", mode);
	return -1;
} 
	
int
get_srk_info(struct srk_info *srk)
{
	char *passwd_ptr = NULL;
	char *secret = NULL;
	int i;

	srk->mode = get_srk_mode();
	if (srk->mode == -1)
		return -1;

	srk->secret = NULL;
	passwd_ptr = getenv("OCK_SRK_SECRET");

	/* If nothing is set, then use original opencryptoki default of
	 *  secret is NULL and TSS_SECRET_MODE_PLAIN. 
	 */
	if (passwd_ptr == NULL) {
		srk->len = 0;
		if (srk->mode == 0) {
			srk->mode = TSS_SECRET_MODE_PLAIN;
			return 0;
		}
	} else
		srk->len = strlen(passwd_ptr);	

	/* A mode required at this point...  */
	if (srk->mode == 0) {
		TRACE_ERROR("SRK policy's secret mode is not set.\n");
		return -1;
	}

	 /*  
	  * getenv() returns a ptr to the actual string in our env,
	  * so be sure to make a copy to avoid problems.
	  */
	
	if (srk->len != 0) {
		if ((secret = (char *)malloc(srk->len)) == NULL) {
			TRACE_ERROR("malloc of %d bytes failed.\n", srk->len);
			return -1;
		}
		memcpy(secret, passwd_ptr, srk->len);
		srk->secret = secret;
	}

	/* Secrets that are a hash, need to be converted from a
	 *  hex string to an array of bytes.
	 */
	if (srk->mode == TSS_SECRET_MODE_SHA1) {

		char *secret_h;
		int h_len = TPM_SHA1_160_HASH_LEN;
		
		if ((secret_h = (char *)malloc(h_len)) == NULL) {
			TRACE_ERROR("malloc of %d bytes failed.\n", h_len);
			goto error;
		}

		/* reuse passwd ptr since we dont need it anymore. */
		passwd_ptr = secret;

		/* Assume hash is read in as string of hexidecimal digits.
		 * 2 hex digits are required to represent a byte.
		 * thus we need 2 * TPM_SHA1_160_HASH_LEN to 
		 * represent the hash.
		 */
		if (srk->len != (h_len * 2)) {
			TRACE_DEVEL("Hashed secret is %d bytes, expected %d.\n",
				     srk->len, h_len*2);
			goto error;
		}

		/* convert hexadecimal string into a byte array... */
		for (i = 0; i < h_len; i++) {
			sscanf(passwd_ptr, "%2hhx", &secret_h[i]);
			passwd_ptr += 2;
		}

		srk->len = h_len;
		srk->secret = secret_h;
		free(secret);
	} 
		
	return	0;

error:
	if (secret) 
		free(secret);
	return -1;
}
