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

CK_RV ock_generic_filter_mechanism_list(STDLL_TokData_t *tokdata,
                                        const MECH_LIST_ELEMENT *list,
                                        CK_ULONG listlen,
                                        MECH_LIST_ELEMENT **reslist,
                                        CK_ULONG *reslen)
{
    CK_ULONG i, j;

    *reslist = calloc(listlen, sizeof(MECH_LIST_ELEMENT));
    if (!*reslist)
        return CKR_HOST_MEMORY;
    for (i = 0, j = 0; i < listlen; ++i) {
        memcpy(*reslist + j, list + i, sizeof(MECH_LIST_ELEMENT));
        if (tokdata->policy->update_mech_info(tokdata->policy,
                                              (*reslist)[j].mech_type,
                                              &(*reslist)[j].mech_info) ==
            CKR_OK)
            ++j;
    }
    *reslen = j;
    *reslist = realloc(*reslist, sizeof(MECH_LIST_ELEMENT) * j);
    return CKR_OK;
}

CK_RV ock_generic_get_mechanism_list(STDLL_TokData_t * tokdata,
                                     CK_MECHANISM_TYPE_PTR pMechanismList,
                                     CK_ULONG_PTR pulCount,
                                     CK_BBOOL (*filter_mechanism)
                                               (STDLL_TokData_t *tokdata,
                                               CK_MECHANISM_TYPE mechanism))
{
    int rc = CKR_OK;
    unsigned int i, j;

    for (i = 0, j = 0; i < tokdata->mech_list_len; i++) {
        if (filter_mechanism == NULL ||
            filter_mechanism(tokdata, tokdata->mech_list[i].mech_type)) {
            if (pMechanismList != NULL) {
                if ((*pulCount) <= j)
                    rc = CKR_BUFFER_TOO_SMALL;
                else
                    pMechanismList[j] = tokdata->mech_list[i].mech_type;
            }
            j++;
        }
    }

    (*pulCount) = j;

    if (rc == CKR_BUFFER_TOO_SMALL) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
    }

    return rc;
}

CK_RV ock_generic_get_mechanism_info(STDLL_TokData_t * tokdata,
                                     CK_MECHANISM_TYPE type,
                                     CK_MECHANISM_INFO_PTR pInfo,
                                     CK_BBOOL (*filter_mechanism)
                                               (STDLL_TokData_t *tokdata,
                                               CK_MECHANISM_TYPE mechanism))
{
    int rc = CKR_OK;
    unsigned int i;

    for (i = 0; i < tokdata->mech_list_len; i++) {
        if (tokdata->mech_list[i].mech_type == type) {
            if (filter_mechanism == NULL || filter_mechanism(tokdata, type)) {
                memcpy(pInfo, &tokdata->mech_list[i].mech_info,
                       sizeof(CK_MECHANISM_INFO));
                goto out;
            } else {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
                rc = CKR_MECHANISM_INVALID;
                goto out;
            }

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
    CK_ULONG i;
    if (getenv("NS_SERVER_HOME") != NULL) {
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
