/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdlib.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

void mech_array_to_list(struct mech_list_item *head,
			MECH_LIST_ELEMENT mech_list_arr[],
			int list_len) {
	int i;
	struct mech_list_item *current;
	current = head;
	for (i = 0; i < list_len; i++) {
		current->next = malloc(sizeof(struct mech_list_item));
		current = current->next;
		memcpy(&current->element, &mech_list_arr[i],
		       sizeof(MECH_LIST_ELEMENT));
	}
}

struct mech_list_item *
find_mech_list_item_for_type(CK_MECHANISM_TYPE type,
			     struct mech_list_item *head)
{
	struct mech_list_item *res;
	res = head->next;
	while (res) {
		if (res->element.mech_type == type) {
			goto out;
		}
		res = res->next;
	}
 out:
	return res;
}

void free_mech_list(struct mech_list_item *head)
{
	struct mech_list_item *walker;
	walker = head->next;
	while (walker) {
		struct mech_list_item *next;
		next = walker->next;
		free(walker);
		walker = next;
	}
}

/**
 * If a type exists in the source that is not in the target, copy it
 * over. If a type exists in both the source and the target, overwrite
 * the target.
 */
void merge_mech_lists(struct mech_list_item *head_of_target,
		      struct mech_list_item *head_of_source)
{

}

CK_RV
ock_generic_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
			       CK_ULONG_PTR pulCount)
{
	int rc = CKR_OK;
	unsigned int i;
	if (pMechanismList == NULL) {
		(*pulCount) = mech_list_len;
		goto out;
	}
	if ((*pulCount) < mech_list_len) {
		(*pulCount) = mech_list_len;
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		rc = CKR_BUFFER_TOO_SMALL;
		goto out;
	}
	for (i=0; i < mech_list_len; i++)
		pMechanismList[i] = mech_list[i].mech_type;
	(*pulCount) = mech_list_len;
 out:
	return rc;
}

CK_RV
ock_generic_get_mechanism_info(CK_MECHANISM_TYPE type,
			       CK_MECHANISM_INFO_PTR pInfo)
{
	int rc = CKR_OK;
	unsigned int i;
	for (i=0; i < mech_list_len; i++) {
		if (mech_list[i].mech_type == type) {
			memcpy(pInfo, &mech_list[i].mech_info,
			       sizeof(CK_MECHANISM_INFO));
			goto out;
		}
	}
	TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
	rc = CKR_MECHANISM_INVALID;
 out:
	return rc;
}

/*
 * For Netscape we want to not support the SSL3 mechs since the native
 * ones perform much better.  Force those slots to be RSA... it's ugly
 * but it works.
 */
static void netscape_hack(CK_MECHANISM_TYPE_PTR mech_arr_ptr, CK_ULONG count)
{
	char *envrn;
	CK_ULONG i;
	if ((envrn = getenv("NS_SERVER_HOME")) != NULL) {
		for (i = 0; i < count; i++) {
			switch (mech_arr_ptr[i]) {
			case CKM_SSL3_PRE_MASTER_KEY_GEN:
			case CKM_SSL3_MASTER_KEY_DERIVE:
			case CKM_SSL3_KEY_AND_MAC_DERIVE:
			case CKM_SSL3_MD5_MAC:
			case CKM_SSL3_SHA1_MAC:
				mech_arr_ptr[i] = CKM_RSA_PKCS;
				break;
			}
		}
	}
}

void mechanism_list_transformations(CK_MECHANISM_TYPE_PTR mech_arr_ptr,
				    CK_ULONG_PTR count_ptr)
{
	netscape_hack(mech_arr_ptr, (*count_ptr));
}
