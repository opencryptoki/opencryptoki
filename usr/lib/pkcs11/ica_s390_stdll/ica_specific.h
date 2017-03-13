/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef __ICA_SPECIFIC_H
#define __ICA_SPECIFIC_H

CK_BBOOL	mech_list_ica_init = FALSE;

typedef struct _REF_MECH_LIST_ELEMENT
{
	CK_ULONG             lica_idx;
	CK_MECHANISM_TYPE    mech_type;
	CK_MECHANISM_INFO    mech_info;
} REF_MECH_LIST_ELEMENT;

extern REF_MECH_LIST_ELEMENT	ref_mech_list[];
extern CK_ULONG		ref_mech_list_len;

CK_RV
ica_specific_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
				CK_ULONG_PTR pulCount);

CK_RV
ica_specific_get_mechanism_info(CK_MECHANISM_TYPE type,
				CK_MECHANISM_INFO_PTR pInfo);

CK_RV
mech_list_ica_initialize(void);

#endif
