/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef OCK_HASHMAP_H
#define OCK_HASHMAP_H

#include <pkcs11types.h>

struct hashmap;

union hashmap_value {
    CK_ULONG ulVal;
    void    *pVal;
};

typedef void (*freefunc_t)(union hashmap_value);

struct hashmap *hashmap_new(void);
void hashmap_free(struct hashmap *h, freefunc_t f);
int hashmap_find(struct hashmap *h, CK_ULONG key, union hashmap_value *val);
int hashmap_add(struct hashmap *h, CK_ULONG key, union hashmap_value val,
                union hashmap_value *oldval);
int hashmap_delete(struct hashmap *h, CK_ULONG key, union hashmap_value *val);

#endif
