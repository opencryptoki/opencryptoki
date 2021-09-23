#include <stdio.h>
#include <string.h>

#include "unittest.h"

#include <mechtable.h>

int checkstring(void)
{
    unsigned int i;
    int idx, res = 0;

    for (i = 0; i < MECHTABLE_NUM_ELEMS; ++i) {
        idx = mechtable_idx_from_string(mechtable_rows[i].string);
        if (idx < 0) {
            fprintf(stderr, "Mechanism %s not found in table!\n",
                    mechtable_rows[i].string);
            res = -1;
        } else if ((unsigned int) idx != i) {
            fprintf(stderr, "Expected mechanism %s at index %u, but query returned %d!\n",
                    mechtable_rows[i].string, i, idx);
            res = -1;
        }
        if (mechrow_from_string(mechtable_rows[i].string) == NULL) {
            fprintf(stderr, "Unable to get row reference for mechanism %s!\n",
                    mechtable_rows[i].string);
            res = -1;
        }
    }
    return res;
}

int checknumeric(void)
{
    unsigned int i;
    int idx, res = 0;

    for (i = 0; i < MECHTABLE_NUM_ELEMS; ++i) {
        idx = mechtable_idx_from_numeric(mechtable_rows[i].numeric);
        if (idx < 0) {
            fprintf(stderr, "Mechanism %lu not found in table!\n",
                    mechtable_rows[i].numeric);
            res = -1;
        } else if ((unsigned int) idx != i) {
            fprintf(stderr, "Expected mechanism %lu at index %u, but query returned %d!\n",
                    mechtable_rows[i].numeric, i, idx);
            res = -1;
        }
        if (mechrow_from_numeric(mechtable_rows[i].numeric) == NULL) {
            fprintf(stderr, "Unable to get row reference for mechanism %lu!\n",
                    mechtable_rows[i].numeric);
            res = -1;
        }
    }
    return res;
}

int checkalias(void)
{
    const struct mechrow *row = mechrow_from_string("CKM_ECDSA_KEY_PAIR_GEN");
    if (row)
        return strcmp(row->string, "CKM_EC_KEY_PAIR_GEN");
    return -1;
}

int checkfailure(void)
{
    int idxnum = mechtable_idx_from_numeric(0xffffffffu);
    int idxstr = mechtable_idx_from_string("CKM_DOES_NOT_EXIST");
    int res = 0;

    if (idxnum != -1) {
        fprintf(stderr, "Did find 0xffffffff which should not be a valid mechanism!\n");
        res = -1;
    }
    if (idxstr != -1) {
        fprintf(stderr, "Did find mechanism CKM_DOES_NOT_EXIST!\n");
        res = -1;
    }
    return res;
}

int main(void)
{
    if (checkstring() || checknumeric() || checkalias() || checkfailure())
        return TEST_FAIL;
    return TEST_PASS;
}
