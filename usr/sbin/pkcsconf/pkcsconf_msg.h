/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _H_PKCSCONF_MSG
#define _H_PKCSCONF_MSG

/* list of mechanism flags and their printable string names */
struct _pkcs11_mech_flags {
    char *name;
    CK_FLAGS flag;
} pkcs11_mech_flags[] = {
    { "CKF_HW", CKF_HW },
    { "CKF_ENCRYPT", CKF_ENCRYPT },
    { "CKF_DECRYPT", CKF_DECRYPT },
    { "CKF_DIGEST", CKF_DIGEST },
    { "CKF_SIGN", CKF_SIGN },
    { "CKF_SIGN_RECOVER", CKF_SIGN_RECOVER },
    { "CKF_VERIFY", CKF_VERIFY },
    { "CKF_VERIFY_RECOVER", CKF_VERIFY_RECOVER },
    { "CKF_GENERATE", CKF_GENERATE },
    { "CKF_GENERATE_KEY_PAIR", CKF_GENERATE_KEY_PAIR },
    { "CKF_WRAP", CKF_WRAP },
    { "CKF_UNWRAP", CKF_UNWRAP },
    { "CKF_DERIVE", CKF_DERIVE },
    { "CKF_EC_F_P", CKF_EC_F_P },
    { "CKF_EC_F_2M", CKF_EC_F_2M },
    { "CKF_EC_ECPARAMETERS", CKF_EC_ECPARAMETERS },
    { "CKF_EC_OID", CKF_EC_OID },
    { "CKF_EC_UNCOMPRESS", CKF_EC_UNCOMPRESS },
    { "CKF_EC_COMPRESS", CKF_EC_COMPRESS },
    { "CKF_EC_CURVENAME", CKF_EC_CURVENAME },
    { "CKF_EXTENSION", CKF_EXTENSION },
    { NULL_PTR, 0xFFFFFFFF }
};

#endif
