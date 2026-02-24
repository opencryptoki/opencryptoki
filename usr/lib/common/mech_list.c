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
#include "p11util.h"
#include "mechtable.h"

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
                                               CK_MECHANISM_TYPE mechanism,
                                               CK_MECHANISM_INFO *info))
{
    int rc = CKR_OK;
    unsigned int i, j;

    for (i = 0, j = 0; i < tokdata->mech_list_len; i++) {
        if (filter_mechanism == NULL ||
            filter_mechanism(tokdata, tokdata->mech_list[i].mech_type, NULL)) {
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
                                               CK_MECHANISM_TYPE mechanism,
                                               CK_MECHANISM_INFO *info))
{
    CK_MECHANISM_INFO info;
    int rc = CKR_OK;
    unsigned int i;

    for (i = 0; i < tokdata->mech_list_len; i++) {
        if (tokdata->mech_list[i].mech_type == type) {
            info = tokdata->mech_list[i].mech_info;
            if (filter_mechanism == NULL ||
                filter_mechanism(tokdata, type, &info)) {
                *pInfo = info;
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

/*
 * Compare the 2 mechanisms alphabetically, this gives the best sorting result.
 */
static int compare_mech(const void *p1, const void *p2, void *arg)
{
    const struct mechtable_funcs *mechtable_funcs = arg;

    return strcmp(p11_get_ckm(mechtable_funcs, *((CK_MECHANISM_TYPE *)p1)),
                  p11_get_ckm(mechtable_funcs, *((CK_MECHANISM_TYPE *)p2)));
}

#if defined(_AIX)
/* This must be a thread local variable ! */
__thread const struct mechtable_funcs *thread_local_mechtable_funcs = NULL;

static int compare_mech_aix(const void *p1, const void *p2)
{
    if (thread_local_mechtable_funcs == NULL)
        return 0;

    return compare_mech(p1, p2, (void *)thread_local_mechtable_funcs);
}
#endif

static void sort_mech_list(STDLL_TokData_t *tokdata,
                           CK_MECHANISM_TYPE_PTR mech_arr_ptr, CK_ULONG count)
{
#if defined(_AIX)
    thread_local_mechtable_funcs = tokdata->mechtable_funcs;
    qsort(mech_arr_ptr, count, sizeof(CK_MECHANISM_TYPE), compare_mech_aix);
    thread_local_mechtable_funcs = NULL;
#else
    qsort_r(mech_arr_ptr, count, sizeof(CK_MECHANISM_TYPE),
            compare_mech, (void *)tokdata->mechtable_funcs);
#endif
}

void mechanism_list_transformations(STDLL_TokData_t *tokdata,
                                    CK_MECHANISM_TYPE_PTR mech_arr_ptr,
                                    CK_ULONG_PTR count_ptr)
{
    if (mech_arr_ptr == NULL)
        return;

    netscape_hack(mech_arr_ptr, (*count_ptr));

    sort_mech_list(tokdata, mech_arr_ptr, (*count_ptr));
}
