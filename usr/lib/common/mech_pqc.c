/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

CK_RV ckm_ibm_dilithium_key_pair_gen(STDLL_TokData_t *tokdata,
                                     TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    const struct pqc_oid *pqc_oid;
    CK_RV rc;

    if (token_specific.t_ibm_dilithium_generate_keypair == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    pqc_oid = ibm_pqc_get_keyform_mode(publ_tmpl, CKM_IBM_DILITHIUM);
    if (pqc_oid == NULL)
        pqc_oid = ibm_pqc_get_keyform_mode(priv_tmpl, CKM_IBM_DILITHIUM);
    if (pqc_oid == NULL)
        pqc_oid = find_pqc_by_keyform(dilithium_oids,
                                      CK_IBM_DILITHIUM_KEYFORM_ROUND2_65);
    if (pqc_oid == NULL) {
        TRACE_ERROR("%s Failed to determine dilithium OID\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    rc = token_specific.t_ibm_dilithium_generate_keypair(tokdata, pqc_oid,
                                                         publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific dilithium keypair generation failed.\n");

    return rc;
}
