/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include <stdio.h>
#include <stdlib.h>

#include <pkcs11types.h>
#include "hashmap.h"

/*
 * Hash map for mechanisms.  It stores the mechanism number in a
 * linked hash map.  Note that it does not directly store the
 * mechanism number, but the mechanism number plus one.  This is done
 * to have 0 represent an empty bucket.  The structure is optimized
 * for the non-chaining case in which case the value is directly
 * stored in the root of the bucket chain.  Only further chain
 * elements are allocated separately.
 *
 * Furthermore, we use a size optimization to not pre-allocate buckets
 * when creating a new hash.  Only on first addition to the hash do we
 * create the bucket list.
 *
 * The hash is a power of 2 hash to speed up hash value computation
 * (subtraction + binary and versus modulo computation).
 */

/* Default hash size has to be a power of 2. */
#define HASH_DEFAULT_CAPA 16

static unsigned int hash(unsigned int capa, CK_ULONG value)
{
#ifdef HASHMAP_FULL_JENKINS
    /* Full Jenkins hash */
    unsigned char *key = (unsigned char *)&value;
    size_t i = 0;
    unsigned int hash = 0;

    while (i != 8) {
        hash += key[i++];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash & (capa - 1);
#else
#  ifdef HASHMAP_JENKINS_MIX
    /* Jenkins hash mix function */
    value += value << 3;
    value ^= value >> 11;
    value += value << 15;
#  endif
    return value & (capa - 1);
#endif
}

struct hashmap_bucket;
struct hashmap_bucket {
    CK_ULONG key;
    union hashmap_value value;
    struct hashmap_bucket *next;
};

struct hashmap {
    struct hashmap_bucket *buckets;
    unsigned int size;
    unsigned int capa;
    freefunc_t freefunc;
};

/* Create size-optimized empty hash.  First add will expand the hash to its
 * default capacity.
 */
struct hashmap *hashmap_new(void)
{
    struct hashmap *res = malloc(sizeof(struct hashmap));
    if (!res)
        return res;
    res->buckets = NULL;
    res->size = 0;
    res->capa = 0;
    return res;
}

static void freebucketchain(struct hashmap_bucket *b, freefunc_t f)
{
    struct hashmap_bucket *n;
    
    while (b) {
        n = b->next;
        if (f)
            f(b->value);
        free(b);
        b = n;
    }
}

static void freebuckets(struct hashmap_bucket *buckets, unsigned int size,
                        freefunc_t f)
{
    unsigned int i;
    
    for (i = 0; i < size; ++i)
        freebucketchain(buckets[i].next, f);
}

void hashmap_free(struct hashmap *h, freefunc_t f)
{
    if (h) {
        if (h->buckets) {
            freebuckets(h->buckets, h->capa, f);
            free(h->buckets);
        }
        free(h);
    }
}

static int do_add(struct hashmap_bucket *buckets, unsigned int size,
                  CK_ULONG key, union hashmap_value val)
{
    unsigned int hval;
    struct hashmap_bucket *newbucket;
    
    hval = hash(size, key);
    if (buckets[hval].key) {
        newbucket = malloc(sizeof(struct hashmap_bucket));
        if (!newbucket)
            return 1;
        newbucket->next = buckets[hval].next;
        newbucket->key = key;
        newbucket->value = val;
        buckets[hval].next = newbucket;
    } else {
        buckets[hval].key = key;
        buckets[hval].value = val;
    }
    return 0;
}

static int grow(struct hashmap *h)
{
    unsigned int i;
    unsigned int newcapa;
    struct hashmap_bucket *newarr, *walk;
    
    newcapa = h->capa ? h->capa << 1 : HASH_DEFAULT_CAPA;
    if (newcapa < h->capa)
        return 1;
    newarr = calloc(newcapa, sizeof(struct hashmap_bucket));
    if (!newarr)
        return 1;
    for (i = 0; i < h->capa; ++i) {
        if (h->buckets[i].key) {
            walk = &h->buckets[i];
            while (walk) {
                if (do_add(newarr, newcapa, walk->key, walk->value)) {
                    /* Pass no free function here since the values are
                       still in the old hash buckets that remain in
                       the hash. */
                    freebuckets(newarr, newcapa, NULL);
                    free(newarr);
                    return 1;
                }
                walk = walk->next;
            }
        }
    }
    if (h->buckets) {
        /* Pass no free function here since we copied the values into
           the new bucket array. */
        freebuckets(h->buckets, h->capa, NULL);
        free(h->buckets);
    }
    h->buckets = newarr;
    h->capa = newcapa;
    return 0;
}

static struct hashmap_bucket *hashmap_findbucket(struct hashmap *h,
                                                 CK_ULONG key)
{
    unsigned int hval;
    struct hashmap_bucket *b = NULL;

    if (h->buckets) {
        hval = hash(h->capa, key + 1);
        b = &h->buckets[hval];
        while (b && b->key != key + 1)
            b = b->next;
    }
    return b;
}

int hashmap_find(struct hashmap *h, CK_ULONG key, union hashmap_value *val)
{
    struct hashmap_bucket *b = 0;

    if (!h)
        /* The non-existing hash is universal. */
        return 1;
    b = hashmap_findbucket(h, key);
    if (b && val)
        *val = b->value;
    return !!b;
}

int hashmap_add(struct hashmap *h, CK_ULONG key, union hashmap_value val,
                union hashmap_value *oldval)
{
    struct hashmap_bucket *b;

    b = hashmap_findbucket(h, key);
    if (b) {
        if (oldval)
            *oldval = b->value;
        b->value = val;
        return 0;
    }
    /* 0.75 fill factor */
    if (h->capa - (h->capa / 4) < h->size + 1) {
        if (grow(h))
            return 1;
    }
    if (do_add(h->buckets, h->capa, key + 1, val))
        return 1;
    h->size++;
    return 0;
}

int hashmap_delete(struct hashmap *h, CK_ULONG key, union hashmap_value *val)
{
    int retval = 0;
    unsigned int hval;
    struct hashmap_bucket *b, **indirect;
    
    if (h->buckets) {
        hval = hash(h->capa, key + 1);
        if (h->buckets[hval].key == key + 1) {
            if (val)
                *val = h->buckets[hval].value;
            if ((b = h->buckets[hval].next) != NULL) {
                h->buckets[hval].key = b->key;
                h->buckets[hval].value = b->value;
                h->buckets[hval].next = b->next;
                free(b);
            } else {
                h->buckets[hval].key = 0;
            }
            retval = 1;
        } else {
            b = h->buckets[hval].next;
            indirect = &h->buckets[hval].next;
            while (b && b->key != key + 1) {
                indirect = &b->next;
                b = b->next;
            }
            if (b) {
                if (val)
                    *val = b->value;
                *indirect = b->next;
                free(b);
                retval = 1;
            }
        }
    }
    h->size -= retval;
    return retval;
}
