/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef OCK_STATISTICS_H
#define OCK_STATISTICS_H

#include <pkcs11types.h>
#include "slotmgr.h"
#include "mechtable.h"
#include "supportedstrengths.h"
#include "policy.h"

/*
 * Statistics are collected in a shared memory segment per user.
 * The statistics shared memory segment has the following layout:
 * - For each configured slot:
 *    - For each supported mechanism:
 *       - one counter (counter_t) for non-key mechanisms (strength=0)
 *       - one counter for each supported strength (counter_t each)
 *
 * The size of the shared segment therefore is:
 *   Num configured slots * num supp.mechanisms * (num supp. strength + 1) *
 *                                                  size of a counter
 */

typedef CK_ULONG counter_t;

#define STAT_MECH_SIZE  ((NUM_SUPPORTED_STRENGTHS + 1) * sizeof(counter_t))
#define STAT_SLOT_SIZE  (MECHTABLE_NUM_ELEMS * STAT_MECH_SIZE)

struct statistics;
typedef struct statistics *statistics_t;

typedef CK_RV (*statistics_increment_f)(struct statistics *statistics,
                                        CK_SLOT_ID slot,
                                        const CK_MECHANISM *mech,
                                        CK_ULONG strength);

#define STATISTICS_FLAG_COUNT_IMPLICIT      (1 << 0)
#define STATISTICS_FLAG_COUNT_INTERNAL      (1 << 1)

struct statistics {
    CK_ULONG flags;
    CK_ULONG num_slots;
    CK_ULONG slot_shm_offsets[NUMBER_SLOTS_MANAGED];
    CK_ULONG shm_size;
    char shm_name[PATH_MAX];
    CK_BYTE *shm_data;
    statistics_increment_f increment_func; /* NULL if statistics disabled */
    struct policy *policy;
};

#define INC_COUNTER(tokdata, sess, mech, key, no_key_strength)              \
    do {                                                                    \
        if ((tokdata)->statistics->increment_func != NULL)                  \
            (tokdata)->statistics->increment_func((tokdata)->statistics,    \
                  (sess)->session_info.slotID, (mech), (key) != NULL ?      \
                  ((OBJECT *)(key))->strength.strength : (no_key_strength));\
    } while (0)

CK_RV statistics_init(struct statistics *statistics,
                      Slot_Mgr_Socket_t *slots_infos, CK_ULONG flags,
                      uid_t uid, struct policy *policy);
void statistics_term(struct statistics *statistics);

#endif
