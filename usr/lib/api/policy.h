/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef OCK_POLICY_H
#define OCK_POLICY_H

#include <pkcs11types.h>
#include "supportedstrengths.h"

#define POLICY_CHECK_DIGEST    0
#define POLICY_CHECK_SIGNATURE 1
#define POLICY_CHECK_VERIFY    2
#define POLICY_CHECK_ENCRYPT   3
#define POLICY_CHECK_DECRYPT   4
#define POLICY_CHECK_KEYGEN    5
#define POLICY_CHECK_DERIVE    6
#define POLICY_CHECK_WRAP      7
#define POLICY_CHECK_UNWRAP    8

struct policy;
typedef struct policy *policy_t;

struct _SESSION;

struct objstrength {
    /* Just the index into the supportedstrengths array. */
    CK_ULONG strength;
    CK_ULONG siglen;
    CK_BBOOL allowed;
};

struct tokstore_strength {
    CK_MECHANISM mk_keygen;
    CK_MECHANISM mk_crypt;
    CK_MECHANISM wrap_crypt;
    /* Next two are just indices into the supportedstrengths array. */
    CK_ULONG     mk_strength;
    CK_ULONG     wrap_strength;
};

/*
 * Helper function to retrieve attribute values from different
 * sources.  This allows us to implement token specific input to the
 * policy while the policy drives the whole determination of strength.
 */
typedef CK_RV (*get_attr_val_f)(void *data,
                                CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE **attr);

/*
 * Helper function to free a returned attribute.
 */
typedef void (*free_attr_f)(void *data, CK_ATTRIBUTE *attr);

/*
 * Stores into `obj` the strength and whether or not the EC is
 * allowed.  Returns CKR_FUNCTION_FAILED if the strength is below the
 * required strength or the curve is not allowed.
 */
typedef CK_RV (*store_object_strength_f)(policy_t p, struct objstrength *s,
                                         get_attr_val_f get_attr_val, void *d,
                                         free_attr_f free_attr,
                                         struct _SESSION *session);

/*
 * Return CKR_FUNCTION_FAILED if the key is not allowed in the current
 * policy.
 */
typedef CK_RV (*is_key_allowed_f)(policy_t p, struct objstrength *s,
                                  struct _SESSION *session);

/*
 * Check if a given mechanism is allowed.  \c check should be one of
 * the \c POLICY_CHECK_* values.
 */
typedef CK_RV (*is_mech_allowed_f)(policy_t p, CK_MECHANISM_PTR mech,
                                   struct objstrength *s, int check,
                                   struct _SESSION *session);

/*
 * Update the mechanism info for a given mechanism to correctly
 * reflect the profile.  Returns CKR_MECHANISM_INVALID if the
 * mechanism is not supported in the current profile either due to the
 * allowed-list or due key size constraints.
 */
typedef CK_RV (*update_mech_info_f)(policy_t p, CK_MECHANISM_TYPE mech,
                                    CK_MECHANISM_INFO_PTR info);

/*
 * Check whether the crypto operations needed by a specific token
 * store are allowed by the policy.  This check only has to be done
 * once since dynamic policy updates are not supported.
 */
typedef CK_RV (*check_token_store_f)(policy_t p, CK_BBOOL newversion,
                                     CK_MECHANISM_TYPE encalgo, CK_SLOT_ID slot,
                                     struct tokstore_strength *ts);

struct policy {
    void *priv;
    CK_BBOOL active;
    store_object_strength_f store_object_strength;
    is_key_allowed_f is_key_allowed;
    is_mech_allowed_f is_mech_allowed;
    update_mech_info_f update_mech_info;
    check_token_store_f check_token_store;
};

/*
 * Load the policy and the strength definition into a pre-allocated struct.
 */
CK_RV policy_load(struct policy *policy);

/*
 * Unload a pre-allocated policy.  This does not free \c policy, but
 * all its contents and resets the policy to an empty one.
 */
void policy_unload(struct policy *policy);

/*
 * Helper function for store_object_strength_f callbacks.  This
 * function extracts the attribute from a template passed as data.  It
 * does not need a corresponding free function.  But either the object
 * has to be locked or it should not be visible yet.
 */
CK_RV policy_get_attr_from_template(void *data,
                                    CK_ATTRIBUTE_TYPE type,
                                    CK_ATTRIBUTE **attr);

#endif
