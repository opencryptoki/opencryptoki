
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
#include <pwd.h>
#include <grp.h>

#include <openssl/rsa.h>

#include <tss/tss.h>

#include "pkcs11/pkcs11types.h"
#include "pkcs11/stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "args.h"
#include "h_extern.h"

#include "tpm_specific.h"

char *
util_create_id(int type)
{
	char *ret = NULL;
	int size = 0;

	switch (type) {
		case TPMTOK_PUB_ROOT_KEY:
			size = TPMTOK_PUB_ROOT_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				st_err_log("CKR_HOST_MEMORY");
				break;
			}

			sprintf(ret, "%s", TPMTOK_PUB_ROOT_KEY_ID);
			break;
		case TPMTOK_ROOT_KEY:
			size = TPMTOK_ROOT_KEY_ID_SIZE + 1;
			if ((ret = malloc(size)) == NULL) {
				st_err_log("CKR_HOST_MEMORY");
				break;
			}

			sprintf(ret, "%s", TPMTOK_ROOT_KEY_ID);
			break;
		case TPMTOK_MIG_ROOT_KEY:
			size = TPMTOK_MIG_ROOT_KEY_ID_SIZE + 2;
			if ((ret = malloc(size)) == NULL) {
				st_err_log("CKR_HOST_MEMORY");
				break;
			}

			sprintf(ret, "%s", TPMTOK_MIG_ROOT_KEY_ID);
			break;
		case TPMTOK_MIG_LEAF_KEY:
			size = TPMTOK_MIG_LEAF_KEY_ID_SIZE + 2;
			if ((ret = malloc(size)) == NULL) {
				st_err_log("CKR_HOST_MEMORY");
				break;
			}

			sprintf(ret, "%s", TPMTOK_MIG_LEAF_KEY_ID);
			break;
		case TPMTOK_USER_LEAF_KEY:
			size = strlen(TPMTOK_USERNAME) + TPMTOK_USER_LEAF_KEY_ID_SIZE + 2;
			if ((ret = malloc(size)) == NULL) {
				st_err_log("CKR_HOST_MEMORY");
				break;
			}

			sprintf(ret, "%s %s", TPMTOK_USERNAME, TPMTOK_USER_LEAF_KEY_ID);
			break;
		case TPMTOK_USER_BASE_KEY:
			size = strlen(TPMTOK_USERNAME) + TPMTOK_USER_BASE_KEY_ID_SIZE + 2;
			if ((ret = malloc(size)) == NULL) {
				st_err_log("CKR_HOST_MEMORY");
				break;
			}

			sprintf(ret, "%s %s", TPMTOK_USERNAME, TPMTOK_USER_BASE_KEY_ID);
			break;
		default:
			LogError("Unknown type passed to %s: %d", __FUNCTION__, type);
			break;
	}

	return ret;
}

int
util_set_file_mode(char *filename, mode_t mode)
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

int
util_create_user_dir(char *loc)
{
	mode_t mode = (S_IRWXU | S_IRWXG);
	struct passwd *user = getpwnam(TPMTOK_USERNAME);
	struct group *group = getgrnam("pkcs11");
	int rc;

	if (user == NULL || group == NULL)
		return -1;

	if (mkdir(loc, mode) == -1) {
		LogError("%s: mkdir: %s", __FUNCTION__, strerror(errno));
		return -1;
	}

	rc = util_set_file_mode(loc, mode);
	rc |= chown(loc, user->pw_uid, group->gr_gid);

	return rc;
}

CK_RV
util_set_username(char **name)
{
	uid_t user_id = getuid();
	struct passwd *pw = NULL;

	/* manpage decrees that errno must be set to 0 if we want to check it on
	 * error.. */
	errno = 0;
	pw = getpwuid(user_id);
	if (pw == NULL) {
		LogError("getpwuid failed: %s", strerror(errno));
		return CKR_FUNCTION_FAILED;
	}

	*name = strdup(pw->pw_name);

	return CKR_OK;
}
