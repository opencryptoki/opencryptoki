
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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include <tss/tss.h>

#include "pkcs11/pkcs11types.h"
#include "pkcs11/stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "args.h"
#include "h_extern.h"

void
LoadBlob_PRIVKEY_DIGEST(UINT16 * offset, BYTE * blob, TCPA_KEY *key)
{
	LoadBlob_TCPA_VERSION(offset, blob, key->ver);
	LoadBlob_UINT16(offset, key->keyUsage, blob);
	LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	blob[(*offset)++] = key->authDataUsage;
	LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);

	LoadBlob_UINT32(offset, key->PCRInfoSize, blob);
	/* exclude pcrInfo when PCRInfoSize is 0 as spec'd in TPM 1.1b spec p.71 */
	if (key->PCRInfoSize != 0)
		LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);

	LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
	/* exclude encSize, encData as spec'd in TPM 1.1b spec p.71 */
}

int
set_file_mode(char *filename, mode_t mode)
{
	struct stat file_stat;

	if (stat(filename, &file_stat) == -1) {
		LogError("%s: stat: %s", __FUNCTION__, strerror(errno));
		return -1;
	} else if ((file_stat.st_mode ^ mode) != 0) {
		if (chmod(filename, mode) == -1) {
			LogError("chmod(%s) failed: %s", filename, strerror(errno));
			return -1;
		}
	}

	return 0;
}
