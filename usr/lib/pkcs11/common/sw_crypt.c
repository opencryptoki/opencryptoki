/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/des.h>
#include <fcntl.h>
#include "pkcs11types.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"
#include "sw_crypt.h"

CK_RV
sw_des3_cbc(CK_BYTE * in_data,
	    CK_ULONG in_data_len,
	    CK_BYTE *out_data,
	    CK_ULONG *out_data_len,
	    CK_BYTE *init_v,
	    CK_BYTE  *key_value,
	    CK_BYTE  encrypt)
{
	DES_key_schedule des_key1;
	DES_key_schedule des_key2;
	DES_key_schedule des_key3;

	const_DES_cblock key_SSL1, key_SSL2, key_SSL3;
	DES_cblock ivec;

	// the des decrypt will only fail if the data length is not evenly divisible
	// by 8
	if (in_data_len % 8) {
		TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
		return CKR_DATA_LEN_RANGE;
	}

	// The key as passed in is a 24 byte string containing 3 keys
	// pick it apart and create the key schedules
	memcpy(&key_SSL1, key_value, (size_t)8);
	memcpy(&key_SSL2, key_value+8, (size_t)8);
	memcpy(&key_SSL3, key_value+16, (size_t)8);
	DES_set_key_unchecked(&key_SSL1, &des_key1);
	DES_set_key_unchecked(&key_SSL2, &des_key2);
	DES_set_key_unchecked(&key_SSL3, &des_key3);

	memcpy(ivec, init_v, sizeof(ivec));

	// Encrypt or decrypt the data
	if (encrypt) {
		DES_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				&des_key1,
				&des_key2,
				&des_key3,
				&ivec,
				DES_ENCRYPT);
		*out_data_len = in_data_len;
	} else {
		DES_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				&des_key1,
				&des_key2,
				&des_key3,
				&ivec,
				DES_DECRYPT);

		*out_data_len = in_data_len;
	}

	return CKR_OK;
}
