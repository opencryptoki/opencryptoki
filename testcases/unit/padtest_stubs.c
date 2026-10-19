/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Stub implementations for padtest
 * These stubs satisfy the external references of utility.c, which is linked
 * into padtest to test add_pkcs_padding() and strip_pkcs_padding(). None of
 * the stubbed functions is called by the code under test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "p11util.h"
#include "attributes.h"
#include "shared_memory.h"

/* Global data */
token_spec_t token_specific = { 0 };

const char manuf[] = "IBM";
const char model[] = "PadTest";
const char descr[] = "IBM padtest";
const char label[] = "padtest";

const CK_BYTE default_so_pin_sha[SHA1_HASH_SIZE] = { 0 };
const CK_BYTE default_so_pin_md5[MD5_HASH_SIZE] = { 0 };

/* loadsave.c */
CK_RV generate_master_key(STDLL_TokData_t *tokdata, CK_BYTE *key)
{
    (void)tokdata;
    (void)key;
    return CKR_FUNCTION_FAILED;
}

CK_RV save_masterkey_so(STDLL_TokData_t *tokdata)
{
    (void)tokdata;
    return CKR_FUNCTION_FAILED;
}

CK_RV save_token_data(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
    (void)tokdata;
    (void)slot_id;
    return CKR_FUNCTION_FAILED;
}

char *get_pk_dir(STDLL_TokData_t *tokdata, char *fname, size_t len)
{
    (void)tokdata;
    (void)fname;
    (void)len;
    return NULL;
}

/* mech_rng.c */
CK_RV rng_generate(STDLL_TokData_t *tokdata, CK_BYTE *output, CK_ULONG bytes)
{
    (void)tokdata;
    (void)output;
    (void)bytes;
    return CKR_FUNCTION_FAILED;
}

/* shared_memory.c */
int sm_open(const char *sm_name, int mode, void **p_addr, size_t len,
            int force, const char *group)
{
    (void)sm_name;
    (void)mode;
    (void)p_addr;
    (void)len;
    (void)force;
    (void)group;
    return -1;
}

int sm_close(void *addr, int destroy, int ignore_ref_count)
{
    (void)addr;
    (void)destroy;
    (void)ignore_ref_count;
    return -1;
}

/* obj_mgr.c */
CK_RV object_mgr_find_in_map1(STDLL_TokData_t *tokdata,
                              CK_OBJECT_HANDLE handle, OBJECT **ptr,
                              OBJ_LOCK_TYPE lock_type)
{
    (void)tokdata;
    (void)handle;
    (void)ptr;
    (void)lock_type;
    return CKR_FUNCTION_FAILED;
}

CK_RV object_put(STDLL_TokData_t *tokdata, OBJECT *obj, CK_BBOOL unlock)
{
    (void)tokdata;
    (void)obj;
    (void)unlock;
    return CKR_FUNCTION_FAILED;
}

/* template.c */
CK_RV template_attribute_get_ulong(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                   CK_ULONG *value)
{
    (void)tmpl;
    (void)type;
    (void)value;
    return CKR_FUNCTION_FAILED;
}

/* attributes.c */
CK_RV get_ulong_attribute_by_type(CK_ATTRIBUTE_PTR attrs,
                                  CK_ULONG attrs_len, CK_ULONG type,
                                  CK_ULONG *value)
{
    (void)attrs;
    (void)attrs_len;
    (void)type;
    (void)value;
    return CKR_FUNCTION_FAILED;
}

CK_RV dup_attribute_array_no_alloc(CK_ATTRIBUTE_PTR orig, CK_ULONG num_attrs,
                                   CK_ATTRIBUTE_PTR dest)
{
    (void)orig;
    (void)num_attrs;
    (void)dest;
    return CKR_FUNCTION_FAILED;
}

/* p11util.c */
CK_BBOOL is_attribute_attr_array(CK_ATTRIBUTE_TYPE type)
{
    (void)type;
    return FALSE;
}
