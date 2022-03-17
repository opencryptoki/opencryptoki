/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "statistics.h"
#include "trace.h"
#include "h_extern.h"
#include "ock_syslog.h"

static CK_RV statistics_increment(struct statistics *statistics,
                                  CK_SLOT_ID slot,
                                  const CK_MECHANISM *mech,
                                  CK_ULONG strength_idx)
{
    CK_ULONG ofs;
    counter_t *counter;
    int mech_idx;
    CK_MECHANISM implicit_mech = { 0, NULL, 0 };
    CK_RV rc;

    if (slot >= NUMBER_SLOTS_MANAGED || strength_idx > POLICY_STRENGTH_IDX_0 ||
        mech == NULL)
        return CKR_ARGUMENTS_BAD;

    ofs = statistics->slot_shm_offsets[slot];
    if (ofs > statistics->shm_size)
        return CKR_SLOT_ID_INVALID;

    mech_idx = mechtable_idx_from_numeric(mech->mechanism);
    if (mech_idx < 0)
        return CKR_MECHANISM_INVALID;

    ofs += mech_idx * (NUM_SUPPORTED_STRENGTHS + 1) * sizeof(counter_t);

    strength_idx = NUM_SUPPORTED_STRENGTHS - strength_idx;
    ofs += strength_idx * sizeof(counter_t);

    if (ofs > statistics->shm_size)
        return CKR_FUNCTION_FAILED;

    counter = (counter_t*)(statistics->shm_data + ofs);
    __sync_add_and_fetch(counter, 1);

    if ((statistics->flags & STATISTICS_FLAG_COUNT_IMPLICIT) == 0)
        return CKR_OK;

    /* deep inspect certain mechanism params for implicit mechanism use */
    switch (mech->mechanism) {
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        implicit_mech.mechanism =
                ((CK_RSA_PKCS_PSS_PARAMS *)mech->pParameter)->hashAlg;
        rc = statistics_increment(statistics, slot, &implicit_mech,
                                  POLICY_STRENGTH_IDX_0);
        if (rc != CKR_OK)
            return rc;

        rc = get_mgf_mech(((CK_RSA_PKCS_PSS_PARAMS *)mech->pParameter)->mgf,
                          &implicit_mech.mechanism);
        if (rc != CKR_OK)
            return rc;
        rc = statistics_increment(statistics, slot, &implicit_mech,
                                  POLICY_STRENGTH_IDX_0);
        if (rc != CKR_OK)
            return rc;
        break;
    case CKM_RSA_PKCS_OAEP:
        implicit_mech.mechanism =
                ((CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter)->hashAlg;
        rc = statistics_increment(statistics, slot, &implicit_mech,
                                  POLICY_STRENGTH_IDX_0);
        if (rc != CKR_OK)
            return rc;

        rc = get_mgf_mech(((CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter)->mgf,
                          &implicit_mech.mechanism);
        if (rc != CKR_OK)
            return rc;
        rc = statistics_increment(statistics, slot, &implicit_mech,
                                  POLICY_STRENGTH_IDX_0);
        if (rc != CKR_OK)
            return rc;
        break;
    case CKM_ECDH1_DERIVE:
        if (((CK_ECDH1_DERIVE_PARAMS *)mech->pParameter)->kdf == CKD_NULL)
            break;
        rc = digest_from_kdf(((CK_ECDH1_DERIVE_PARAMS *)mech->pParameter)->kdf,
                             &implicit_mech.mechanism);
        if (rc != CKR_OK)
            return rc;
        rc = statistics_increment(statistics, slot, &implicit_mech,
                                  POLICY_STRENGTH_IDX_0);
        if (rc != CKR_OK)
            return rc;
        break;
    default:
        break;
    }

    return CKR_OK;
}

/*
 * Open the statistics shared memory segment for the specified user.
 * If user is -1, then it is opened for the current user.
 * If create is TRUE then the shared memory segment is created if it is not
 * already existent.
 */
static CK_RV statistics_open_shm(struct statistics *statistics, int user,
                                 CK_BBOOL create)
{
    int i, err, clear = 0;
    struct stat stat_buf;

    snprintf(statistics->shm_name, sizeof(statistics->shm_name) - 1,
             "%s_stats_%u", CONFIG_PATH, user == -1 ? geteuid() : (uid_t)user);
    for (i = 1; statistics->shm_name[i] != '\0'; i++) {
        if (statistics->shm_name[i] == '/')
            statistics->shm_name[i] = '.';
    }
    if (statistics->shm_name[0] != '/') {
        memmove(&statistics->shm_name[1], &statistics->shm_name[0],
                strlen(statistics->shm_name) + 1);
        statistics->shm_name[0] = '/';
    }

    TRACE_INFO("Statistics SHM name: '%s'\n", statistics->shm_name);

    statistics->shm_handle = shm_open(statistics->shm_name, O_RDWR,
                                      S_IRUSR | S_IWUSR);
    if (statistics->shm_handle == -1) {
        if (create) {
            /* try to create it */
            statistics->shm_handle = shm_open(statistics->shm_name,
                                              O_CREAT | O_RDWR,
                                              S_IRUSR | S_IWUSR);
            if (statistics->shm_handle == -1) {
                err = errno;
                TRACE_ERROR("Failed to create SHM '%s': %s\n",
                            statistics->shm_name,  strerror(err));
                OCK_SYSLOG(LOG_ERR, "Failed to create SHM '%s': %s\n",
                           statistics->shm_name, strerror(err));
                return CKR_FUNCTION_FAILED;
            }

            if (fchmod(statistics->shm_handle, S_IRUSR | S_IWUSR) == -1) {
                err = errno;
                TRACE_ERROR("Failed to change mode of SHM '%s': %s\n",
                            statistics->shm_name,  strerror(err));
                OCK_SYSLOG(LOG_ERR, "Failed to change mode of SHM '%s': %s\n",
                           statistics->shm_name, strerror(err));
                close(statistics->shm_handle);
                shm_unlink(statistics->shm_name);
                return CKR_FUNCTION_FAILED;
            }
        } else {
            err = errno;
            TRACE_ERROR("Failed to open SHM '%s': %s\n",
                        statistics->shm_name,  strerror(err));
            OCK_SYSLOG(LOG_ERR, "Failed to open SHM '%s': %s\n",
                       statistics->shm_name, strerror(err));
            return CKR_FUNCTION_FAILED;
        }
    }

    if (fstat(statistics->shm_handle, &stat_buf)) {
        err = errno;
        TRACE_ERROR("Failed to stat SHM '%s': %s\n",
                    statistics->shm_name,  strerror(err));
        OCK_SYSLOG(LOG_ERR, "Failed to stat SHM '%s': %s\n",
                   statistics->shm_name, strerror(err));
        close(statistics->shm_handle);
        return CKR_FUNCTION_FAILED;
    }

    /*
     * If the shared memory segment does not belong to the current user or does
     * not have correct permissions, do not use it.
     */
    if (stat_buf.st_uid != geteuid() ||
        (stat_buf.st_mode & ~S_IFMT) != (S_IRUSR | S_IWUSR)) {
        TRACE_ERROR("SHM '%s' has wrong mode/owner\n", statistics->shm_name);
        OCK_SYSLOG(LOG_ERR, "SHM '%s' has wrong mode/owner\n",
                   statistics->shm_name);
        close(statistics->shm_handle);
        return CKR_FUNCTION_FAILED;
    }

    if ((CK_ULONG)stat_buf.st_size != statistics->shm_size) {
        if (create) {
            if (ftruncate(statistics->shm_handle, statistics->shm_size) < 0) {
                err = errno;
                TRACE_ERROR("Failed to set size of SHM '%s': %s\n",
                            statistics->shm_name,  strerror(err));
                OCK_SYSLOG(LOG_ERR, "Failed to set size of SHM '%s': %s\n",
                           statistics->shm_name, strerror(err));
                close(statistics->shm_handle);
                return CKR_FUNCTION_FAILED;
            }

            clear = 1;
        } else {
            TRACE_ERROR("SHM '%s' has wrong size\n", statistics->shm_name);
            OCK_SYSLOG(LOG_ERR, "SHM '%s' has wrong size\n",
                       statistics->shm_name);
            return CKR_FUNCTION_FAILED;
        }
    }

    statistics->shm_data = (CK_BYTE *)mmap(NULL, statistics->shm_size,
                                           PROT_READ | PROT_WRITE, MAP_SHARED,
                                           statistics->shm_handle, 0);
    if (statistics->shm_data == MAP_FAILED) {
        err = errno;
        TRACE_ERROR("Failed to memory-map SHM '%s': %s\n",
                    statistics->shm_name, strerror(err));
        OCK_SYSLOG(LOG_ERR, "Failed to memory-map SHM '%s': %s\n",
                   statistics->shm_name, strerror(err));
        close(statistics->shm_handle);
        statistics->shm_data = NULL;
        return CKR_FUNCTION_FAILED;
    }

    if (clear)
        memset(statistics->shm_data, 0, sizeof(statistics->shm_size));

    return CKR_OK;
}

static CK_RV statistics_close_shm(struct statistics *statistics,
                                  CK_BBOOL destroy)
{
    CK_RV rc;

    if (statistics->shm_data == NULL || statistics->shm_handle == -1)
        return CKR_ARGUMENTS_BAD;

    munmap(statistics->shm_data, statistics->shm_size);
    close(statistics->shm_handle);

    if (destroy) {
        rc = shm_unlink(statistics->shm_name);
        if (rc != 0) {
            TRACE_ERROR("Failed to unlink SHM '%s': %s\n",
                        statistics->shm_name,  strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }

    statistics->shm_data = NULL;
    statistics->shm_size = -1;

    return CKR_OK;
}

CK_RV statistics_init(struct statistics *statistics,
                      Slot_Mgr_Socket_t *slots_infos, CK_ULONG flags,
                      uid_t uid)
{
    CK_ULONG i;
    CK_RV rc;

    statistics->flags = flags;
    statistics->shm_handle = -1;
    statistics->shm_data = NULL;

    /* Count number of configured slots and calculate slot offsets. */
    statistics->num_slots = 0;
    for (i = 0; i < NUMBER_SLOTS_MANAGED; i++) {
        if (slots_infos->slot_info[i].present) {
            statistics->slot_shm_offsets[i] =
                        statistics->num_slots * STAT_SLOT_SIZE;
            statistics->num_slots++;
        } else {
            statistics->slot_shm_offsets[i] = (CK_ULONG)-1;
        }
    }
    statistics->shm_size = statistics->num_slots * STAT_SLOT_SIZE;

    TRACE_INFO("%lu slots defined\n", statistics->num_slots);
    TRACE_INFO("Statistics SHM size: %lu\n", statistics->shm_size);

    rc = statistics_open_shm(statistics, uid, CK_TRUE);
    if (rc != CKR_OK)
        goto error;

    statistics->increment_func = statistics_increment;

    return CKR_OK;

error:
    statistics_term(statistics);
    return rc;
}

void statistics_term(struct statistics *statistics)
{
    statistics_close_shm(statistics, CK_FALSE);
}

