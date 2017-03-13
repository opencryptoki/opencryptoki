/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef __SW_CRYPT_H__
#define __SW_CRYPT_H__

#define sw_des3_cbc_encrypt(clear, len, cipher, len2, iv, key) \
	sw_des3_cbc(clear, len, cipher, len2, iv, key, 1)

#define sw_des3_cbc_decrypt(clear, len, cipher, len2, iv, key) \
	sw_des3_cbc(clear, len, cipher, len2, iv, key, 0)

CK_RV
sw_des3_cbc(CK_BYTE * in_data,
	    CK_ULONG in_data_len,
	    CK_BYTE *out_data,
	    CK_ULONG *out_data_len,
	    CK_BYTE *init_v,
	    CK_BYTE  *key_value,
	    CK_BYTE  encrypt);

#endif
