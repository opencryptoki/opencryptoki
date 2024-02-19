/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include "hashmap.h"
#include "unittest.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include "platform.h"

static int testhashcollisionexpansion(void)
{
    CK_ULONG values[] =
        {
         /* First 12 values that should end up in the same bucket if
            simplest hash function is used.  Make sure they also end
            up in the same bucket after the first expansion. */
         0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800, 0x900,
         0xa00, 0xb00,
         /* Next 12 values that should also end up in the same bucket
            after the expansion. */
         0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1600, 0x1700, 0x1800,
         0x1900, 0x0a00, 0x1b00
        };
    union hashmap_value val = { .ulVal = 0 };
    struct hashmap *h;
    unsigned long i;
    int res = 0;

    h = hashmap_new();
    if (!h) {
        fprintf(stderr, "Failed to allocate mesh hash\n");
        return -1;
    }
    for (i = 0; i < ARRAYSIZE(values) / 2; ++i) {
        if (hashmap_add(h, values[i], val, NULL)) {
            fprintf(stderr, "Failed to add element %lu to meshhash\n", i);
            res = -1;
            goto out;
        }
    }
    for (i = 0; i < ARRAYSIZE(values) / 2; ++i) {
        if (!hashmap_find(h, values[i], NULL)) {
            fprintf(stderr, "Lost element %lu (%lu) in hashmap\n",
                    i, values[i]);
            res = -1;
            goto out;
        }
    }
    for ( ; i < ARRAYSIZE(values); ++i) {
        if (hashmap_add(h, values[i], val, NULL)) {
            fprintf(stderr, "Failed to add element %lu to meshhash\n", i);
            res = -1;
            goto out;
        }
    }
    for (i = 0; i < ARRAYSIZE(values); ++i) {
        if (!hashmap_find(h, values[i], NULL)) {
            fprintf(stderr,
                    "Lost element %lu (%lu) in hashmap after expansion\n",
                    i, values[i]);
            res = -1;
            goto out;
        }
    }
 out:
    hashmap_free(h, NULL);
    return res;
}

static int compareulong(const void *a, const void *b)
{
    unsigned long la = *(const unsigned long *)a;
    unsigned long lb = *(const unsigned long *)b;

    if (la < lb)
        return -1;
    if (la == lb)
        return 0;
    return 1;
}

static int testhashrandom(unsigned long seed, unsigned long iterations)
{
    unsigned long i, *arr, mid, unsucccnt;
    union hashmap_value val = { .ulVal = 0};
    struct hashmap *h;
    int res = 0;

    h = hashmap_new();
    if (!h) {
        fprintf(stderr, "Could not allocate hashmap\n");
        return -1;
    }
    arr = calloc(iterations, sizeof(unsigned long));
    if (!arr) {
        fprintf(stderr, "Failed to allocate data array\n");
        res = -1;
        goto out;
    }
    srandom(seed);
    for (i = 0; i < iterations; ++i)
        arr[i] = random();
    for (i = 0; i < iterations; ++i) {
        if (hashmap_add(h, arr[i], val, NULL)) {
            fprintf(stderr, "Failed to add %lu to hash\n", arr[i]);
            res = -1;
            goto out;
        }
    }
    /* successful searches */
    for (i = 0; i < iterations; ++i) {
        if (!hashmap_find(h, arr[i], NULL)) {
            fprintf(stderr, "Failed to find %lu in hash\n", arr[i]);
            res = -1;
            goto out;
        }
    }
    /* unsuccessful searches */
    unsucccnt = 0;
    qsort(arr, iterations, sizeof(unsigned long), compareulong);
    for (i = 0; i < iterations - 1; ++i) {
        mid = arr[i] + (arr[i + 1] - arr[i]) / 2;
        if (mid != arr[i]) {
            ++unsucccnt;
            if (hashmap_find(h, mid, NULL)) {
                fprintf(stderr, "Found non-existing element %lu in hash\n",
                        mid);
                res = -1;
                goto out;
            }
        }
    }
    fprintf(stderr, "Performed %lu (expected) unsuccessful searches\n",
            unsucccnt);
 out:
    free(arr);
    hashmap_free(h, NULL);
    return res;
}

static int parseulong(const char *str, unsigned long *res)
{
    unsigned long tmp;
    char *endptr;

    errno = 0;
    tmp = strtoul(str, &endptr, 0);
    if (*endptr || (tmp == ULONG_MAX && errno == ERANGE))
        return 1;
    *res = tmp;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned long seed = 0, iterations = 100;
    static struct option long_options[] =
        {
         {"seed",       required_argument, 0, 's'},
         {"iterations", required_argument, 0, 'i'},
         {0,            0,                 0, 0  }
        };
    int c;

    while (1) {
        c = getopt_long(argc, argv, "s:i:", long_options, NULL);
        if (c == -1)
            break;
        switch(c) {
        case 's':
            if (parseulong(optarg, &seed)) {
                fprintf(stderr, "Seed could not be parsed!\n");
                return TEST_SKIP;
            }
            break;
        case 'i':
            if (parseulong(optarg, &iterations)) {
                fprintf(stderr, "Iterations could not be parsed!\n");
                return TEST_SKIP;
            }
            break;
        default:
            printf("USAGE: %s [-s|--seed <num>] [-i|--iterations <num>]\n",
                   argv[0]);
            printf("where the parameters configure the random hash test:\n");
            printf("-s or --seed specifies the random seed\n");
            printf("-i or --iterations specifies the number of iterations to perform\n");
            return TEST_SKIP;
        }
    }
    if (testhashcollisionexpansion())
        return TEST_FAIL;
    if (testhashrandom(seed, iterations))
        return TEST_FAIL;
    /* hashmap_delete function is untested since it is unused so far */
    return TEST_PASS;
}
