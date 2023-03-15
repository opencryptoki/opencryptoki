/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <dirent.h>

#include <slotmgr.h>

#ifdef OCK_TOOL
#include "pkcs_utils.h"
#else
#include "trace.h"
#endif
#include "hsm_mk_change.h"
#include "pkcs32.h"

struct hsm_mk_change_op_hdr {
    char id[6];
    uint32_t state; /* stored in big endian */
};

struct hsm_mkvp_hdr {
    uint32_t type; /* stored in big endian */
    uint32_t mkvp_len; /* stored in big endian */
    /* Followed by mkvp_len bytes MKVP. */
};

static int hsm_mk_change_lock_fd = -1;

CK_RV hsm_mk_change_lock_create(void)
{
    struct group *grp;
    mode_t mode = (S_IRUSR | S_IRGRP);

    if (hsm_mk_change_lock_fd == -1)
        hsm_mk_change_lock_fd = open(OCK_HSM_MK_CHANGE_LOCK_FILE, O_RDONLY);

    if (hsm_mk_change_lock_fd == -1) {
        hsm_mk_change_lock_fd = open(OCK_HSM_MK_CHANGE_LOCK_FILE,
                                     O_CREAT | O_RDONLY, mode);

        if (hsm_mk_change_lock_fd != -1) {
            if (fchmod(hsm_mk_change_lock_fd, mode) == -1) {
                TRACE_ERROR("%s fchmod(%s): %s\n", __func__,
                            OCK_HSM_MK_CHANGE_LOCK_FILE, strerror(errno));
                goto error;
            }

            grp = getgrnam("pkcs11");
            if (grp != NULL) {
                if (fchown(hsm_mk_change_lock_fd, -1, grp->gr_gid) == -1) {
                    TRACE_ERROR("%s fchown(%s): %s\n", __func__,
                                OCK_HSM_MK_CHANGE_LOCK_FILE, strerror(errno));
                    goto error;
                }
            } else {
                TRACE_ERROR("%s getgrnam(): %s\n", __func__, strerror(errno));
                goto error;
            }
        } else  {
            TRACE_ERROR("%s open(%s): %s\n", __func__,
                        OCK_HSM_MK_CHANGE_LOCK_FILE, strerror(errno));
            goto error;
        }
    }

    return CKR_OK;

error:
    if (hsm_mk_change_lock_fd != -1)
        close(hsm_mk_change_lock_fd);

    return CKR_CANT_LOCK;
}

void hsm_mk_change_lock_destroy(void)
{
    if (hsm_mk_change_lock_fd != -1)
        close(hsm_mk_change_lock_fd);
    hsm_mk_change_lock_fd = -1;
}

CK_RV hsm_mk_change_lock(int exclusive)
{
    if (hsm_mk_change_lock_fd == -1)
        return CKR_CANT_LOCK;

    if (flock(hsm_mk_change_lock_fd, exclusive ? LOCK_EX : LOCK_SH) != 0) {
        TRACE_ERROR("%s flock(%s, %s): %s\n", __func__,
                    OCK_HSM_MK_CHANGE_LOCK_FILE,
                    exclusive ? "LOCK_EX" : "LOCK_SH", strerror(errno));
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV hsm_mk_change_unlock(void)
{
    if (hsm_mk_change_lock_fd == -1)
        return CKR_CANT_LOCK;

    if (flock(hsm_mk_change_lock_fd, LOCK_UN) != 0) {
        TRACE_ERROR("%s flock(%s, LOCK_UN): %s\n", __func__,
                    OCK_HSM_MK_CHANGE_LOCK_FILE, strerror(errno));
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV hsm_mk_change_apqns_flatten(const struct apqn *apqns,
                                  unsigned int num_apqns, unsigned char *buff,
                                  size_t *buff_len)
{
    size_t len = sizeof(uint32_t) + num_apqns * sizeof(struct apqn);
    struct apqn *apqn;
    unsigned int i;

    if (buff == NULL) {
        *buff_len = len;
        return CKR_OK;
    }

    if (*buff_len < len) {
        TRACE_ERROR("buffer too small\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    *buff_len = len;

    TRACE_DEBUG("Num APQNs: %u\n", num_apqns);

    *((uint32_t *)buff) = htobe32(num_apqns);
    buff += sizeof(uint32_t);

    for (i = 0; i < num_apqns; i++) {
        TRACE_DEBUG("APQN %d: %02x.%04x\n", i, apqns[i].card, apqns[i].domain);

        apqn = (struct apqn *)buff;
        apqn->card = htobe16(apqns[i].card);
        apqn->domain = htobe16(apqns[i].domain);
        buff += sizeof(struct apqn);
    }

    return CKR_OK;
}

CK_RV hsm_mk_change_apqns_unflatten(const unsigned char *buff, size_t buff_len,
                                    size_t *bytes_read, struct apqn **apqns,
                                    unsigned int *num_apqns)
{
    struct apqn *apqn;
    unsigned int i;
    CK_RV rc;

    if (buff_len < sizeof(uint32_t)) {
        TRACE_ERROR("buffer too small\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    *num_apqns = be32toh(*((uint32_t *)buff));
    buff += sizeof(uint32_t);
    *bytes_read = sizeof(uint32_t);

    TRACE_DEBUG("Num APQNs: %u\n", *num_apqns);

    if (*num_apqns > 0) {
        *apqns = calloc(*num_apqns, sizeof(struct apqn));
        if (*apqns == NULL) {
            TRACE_ERROR("malloc failed\n");
            *num_apqns = 0;
            return CKR_HOST_MEMORY;
        }
    }

    if (buff_len < sizeof(uint32_t) + *num_apqns * sizeof(struct apqn)) {
        TRACE_ERROR("buffer too small\n");
        rc = CKR_BUFFER_TOO_SMALL;
        goto error;
    }

    for (i = 0; i < *num_apqns; i++) {
        apqn = (struct apqn *)buff;

        (*apqns)[i].card = be16toh(apqn->card);
        (*apqns)[i].domain = be16toh(apqn->domain);
        buff += sizeof(struct apqn);
        *bytes_read += sizeof(struct apqn);

        TRACE_DEBUG("APQN %d: %02x.%04x\n", i, (*apqns)[i].card,
                    (*apqns)[i].domain);
    }

    return CKR_OK;

error:
    free(*apqns);
    *apqns = NULL;
    *num_apqns = 0;

    return rc;
}

int hsm_mk_change_apqns_find(const struct apqn *apqns, unsigned int num_apqns,
                             unsigned short card, unsigned short domain)
{
    unsigned int i;

    for (i = 0; i < num_apqns; i++) {
        if (apqns[i].card == card && apqns[i].domain == domain)
            return 1;
    }

    return 0;
}

void hsm_mk_change_mkvps_clean(struct hsm_mkvp *mkvps, unsigned int num_mkvps)
{
   unsigned int i;

   for (i = 0; i < num_mkvps; i++) {
       if (mkvps[i].mkvp != NULL)
           free(mkvps[i].mkvp);
   }

   memset(mkvps, 0, num_mkvps * sizeof(struct hsm_mkvp));
}

CK_RV hsm_mk_change_mkvps_flatten(const struct hsm_mkvp *mkvps,
                                  unsigned int num_mkvps, unsigned char *buff,
                                  size_t *buff_len)
{
    size_t len = sizeof(uint32_t);
    struct hsm_mkvp_hdr *hdr;
    unsigned int i;

    for (i = 0; i < num_mkvps; i++)
        len += sizeof(struct hsm_mkvp_hdr) + mkvps[i].mkvp_len;

    if (buff == NULL) {
        *buff_len = len;
        return CKR_OK;
    }

    if (*buff_len < len) {
        TRACE_ERROR("buffer too small\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    *buff_len = len;

    TRACE_DEBUG("Num MKVPs: %u\n", num_mkvps);

    *((uint32_t *)buff) = htobe32(num_mkvps);
    buff += sizeof(uint32_t);

    for (i = 0; i < num_mkvps; i++) {
        TRACE_DEBUG("MKVP %d: type: %d len %u\n", i, mkvps[i].type,
                    mkvps[i].mkvp_len);
        TRACE_DEBUG_DUMP("MKVP: ", mkvps[i].mkvp, mkvps[i].mkvp_len);

        hdr = (struct hsm_mkvp_hdr *)buff;
        hdr->type = htobe32(mkvps[i].type);
        hdr->mkvp_len = htobe32(mkvps[i].mkvp_len);
        buff += sizeof(struct hsm_mkvp_hdr);

        memcpy(buff, mkvps[i].mkvp, mkvps[i].mkvp_len);
        buff += mkvps[i].mkvp_len;
    }

    return CKR_OK;
}

CK_RV hsm_mk_change_mkvps_unflatten(const unsigned char *buff, size_t buff_len,
                                    size_t *bytes_read, struct hsm_mkvp **mkvps,
                                    unsigned int *num_mkvps)
{
    struct hsm_mkvp_hdr *hdr;
    unsigned int i;
    CK_RV rc;

    if (buff_len < sizeof(uint32_t)) {
        TRACE_ERROR("buffer too small\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    *num_mkvps = be32toh(*((uint32_t *)buff));
    buff += sizeof(uint32_t);
    buff_len -= sizeof(uint32_t);
    *bytes_read = sizeof(uint32_t);

    TRACE_DEBUG("Num MKVPs: %u\n", *num_mkvps);

    if (*num_mkvps > 0) {
        *mkvps = calloc(*num_mkvps, sizeof(struct hsm_mkvp));
        if (*mkvps == NULL) {
            TRACE_ERROR("malloc failed\n");
            *num_mkvps = 0;
            return CKR_HOST_MEMORY;
        }
    }

    for (i = 0; i < *num_mkvps; i++) {
        if (buff_len < sizeof(struct hsm_mkvp_hdr)) {
            TRACE_ERROR("buffer too small\n");
            rc = CKR_BUFFER_TOO_SMALL;
            goto error;
        }

        hdr = (struct hsm_mkvp_hdr *)buff;
        (*mkvps)[i].type = be32toh(hdr->type);
        (*mkvps)[i].mkvp_len = be32toh(hdr->mkvp_len);
        buff += sizeof(struct hsm_mkvp_hdr);
        buff_len -= sizeof(struct hsm_mkvp_hdr);
        *bytes_read += sizeof(struct hsm_mkvp_hdr);

        if (buff_len < (*mkvps)[i].mkvp_len) {
            TRACE_ERROR("buffer too small\n");
            rc = CKR_BUFFER_TOO_SMALL;
            goto error;
        }

        (*mkvps)[i].mkvp = calloc(1, (*mkvps)[i].mkvp_len);
        if ((*mkvps)[i].mkvp == NULL) {
            TRACE_ERROR("malloc failed\n");
            rc = CKR_HOST_MEMORY;
            goto error;
        }

        memcpy((*mkvps)[i].mkvp, buff, (*mkvps)[i].mkvp_len);
        buff += (*mkvps)[i].mkvp_len;
        buff_len -= (*mkvps)[i].mkvp_len;
        *bytes_read += (*mkvps)[i].mkvp_len;

        TRACE_DEBUG("MKVP %d: type: %d len %u\n", i, (*mkvps)[i].type,
                    (*mkvps)[i].mkvp_len);
        TRACE_DEBUG_DUMP("MKVP: ", (*mkvps)[i].mkvp, (*mkvps)[i].mkvp_len);
    }

    return CKR_OK;

error:
    hsm_mk_change_mkvps_clean(*mkvps, *num_mkvps);
    free(*mkvps);
    *mkvps = NULL;
    *num_mkvps = 0;

    return rc;
}

const unsigned char *hsm_mk_change_mkvps_find(const struct hsm_mkvp *mkvps,
                                              unsigned int num_mkvps,
                                              enum hsm_mk_type type,
                                              unsigned int mkvp_len)
{
    unsigned int i;

    for (i = 0; i < num_mkvps; i++) {
        if (mkvps[i].type == type &&
            (mkvp_len == 0 || mkvps[i].mkvp_len == mkvp_len))
            return mkvps[i].mkvp;
    }

    return NULL;
}

void hsm_mk_change_info_clean(struct hsm_mk_change_info *info)
{
    unsigned int i;

    if (info->apqns != NULL)
        free(info->apqns);

    if (info->mkvps != NULL) {
        for (i = 0; i < info->num_mkvps; i++) {
            if (info->mkvps[i].mkvp != NULL)
                free(info->mkvps[i].mkvp);
        }
        free(info->mkvps);
    }

    memset(info, 0, sizeof(*info));
}

CK_RV hsm_mk_change_info_flatten(const struct hsm_mk_change_info *info,
                                 unsigned char *buff, size_t *buff_len)
{
    size_t apqns_len, mkvps_len;
    CK_RV rc;

    rc = hsm_mk_change_apqns_flatten(info->apqns, info->num_apqns,
                                     NULL, &apqns_len);
    if (rc != CKR_OK)
        return rc;

    rc = hsm_mk_change_mkvps_flatten(info->mkvps, info->num_mkvps,
                                     NULL, &mkvps_len);
    if (rc != CKR_OK)
        return rc;

    if (buff == NULL) {
        *buff_len = apqns_len + mkvps_len;
        return CKR_OK;
    }

    if (*buff_len < apqns_len + mkvps_len) {
        TRACE_ERROR("buffer too small\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    *buff_len = apqns_len + mkvps_len;

    rc = hsm_mk_change_apqns_flatten(info->apqns, info->num_apqns,
                                     buff, &apqns_len);
    if (rc != CKR_OK)
        return rc;

    rc = hsm_mk_change_mkvps_flatten(info->mkvps, info->num_mkvps,
                                     buff + apqns_len, &mkvps_len);
    if (rc != CKR_OK)
        return rc;

    return CKR_OK;
}

CK_RV hsm_mk_change_info_unflatten(const unsigned char *buff, size_t buff_len,
                                   size_t *bytes_read,
                                   struct hsm_mk_change_info *info)
{
    size_t apqns_read = 0, mkvps_read = 0;
    CK_RV rc;

    hsm_mk_change_info_clean(info);

    rc = hsm_mk_change_apqns_unflatten(buff, buff_len, &apqns_read,
                                       &info->apqns, &info->num_apqns);
    if (rc != CKR_OK) {
        hsm_mk_change_info_clean(info);
        return rc;
    }

    rc = hsm_mk_change_mkvps_unflatten(buff + apqns_read, buff_len - apqns_read,
                                       &mkvps_read,
                                       &info->mkvps, &info->num_mkvps);
    if (rc != CKR_OK) {
        hsm_mk_change_info_clean(info);
        return rc;
    }

    *bytes_read = apqns_read + mkvps_read;

    return CKR_OK;
}

CK_RV hsm_mk_change_slots_flatten(const CK_SLOT_ID *slots,
                                  unsigned int num_slots, unsigned char *buff,
                                  size_t *buff_len)
{
    size_t len = sizeof(uint32_t) + num_slots * sizeof(CK_SLOT_ID_32);
    CK_SLOT_ID_32 *slot;
    unsigned int i;

    if (buff == NULL) {
        *buff_len = len;
        return CKR_OK;
    }

    if (*buff_len < len) {
        TRACE_ERROR("buffer too small\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    *buff_len = len;

    TRACE_DEBUG("Num Slots: %u\n", num_slots);

    *((uint32_t *)buff) = htobe32(num_slots);
    buff += sizeof(uint32_t);

    for (i = 0; i < num_slots; i++) {
        TRACE_DEBUG("Slot %d: %lu\n", i, slots[i]);

        slot = (CK_SLOT_ID_32 *)buff;
        *slot = htobe32(slots[i]);
        buff += sizeof(CK_SLOT_ID_32);
    }

    return CKR_OK;
}

CK_RV hsm_mk_change_slots_unflatten(const unsigned char *buff, size_t buff_len,
                                    size_t *bytes_read, CK_SLOT_ID **slots,
                                    unsigned int *num_slots)
{
    CK_SLOT_ID_32 *slot;
    unsigned int i;
    CK_RV rc;

    if (buff_len < sizeof(uint32_t)) {
        TRACE_ERROR("buffer too small\n");
        return CKR_BUFFER_TOO_SMALL;
    }

    *num_slots = be32toh(*((uint32_t *)buff));
    buff += sizeof(uint32_t);
    *bytes_read = sizeof(uint32_t);

    TRACE_DEBUG("Num Slots: %u\n", *num_slots);

    if (*num_slots > 0) {
        *slots = calloc(*num_slots, sizeof(CK_SLOT_ID));
        if (*slots == NULL) {
            TRACE_ERROR("malloc failed\n");
            *num_slots = 0;
            return CKR_HOST_MEMORY;
        }
    }

    if (buff_len < sizeof(uint32_t) + *num_slots * sizeof(CK_SLOT_ID_32)) {
        TRACE_ERROR("buffer too small\n");
        rc = CKR_BUFFER_TOO_SMALL;
        goto error;
    }

    for (i = 0; i < *num_slots; i++) {
        slot = (CK_SLOT_ID_32 *)buff;
        (*slots)[i] = be32toh(*slot);
        buff += sizeof(CK_SLOT_ID_32);
        *bytes_read += sizeof(CK_SLOT_ID_32);

        TRACE_DEBUG("Slot %d: %lu\n", i, (*slots)[i]);
    }

    return CKR_OK;

error:
    free(*slots);
    *slots = NULL;
    *num_slots = 0;

    return rc;
}

void hsm_mk_change_op_clean(struct hsm_mk_change_op *op)
{
    hsm_mk_change_info_clean(&op->info);
    if (op->slots != NULL)
        free(op->slots);
    memset(op, 0, sizeof(*op));
}

static void hsm_mk_change_op_set_perm(int file)
{
    struct group *grp;

    // Set absolute permissions or rw-rw----
    fchmod(file, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

    grp = getgrnam("pkcs11"); // Obtain the group id
    if (grp) {
        // set ownership to pkcs11 group
        if (fchown(file, -1, grp->gr_gid) != 0) {
            goto error;
        }
    } else {
        goto error;
    }

    return;

error:
    TRACE_DEVEL("Unable to set permissions on file.\n");
}

static FILE* hsm_mk_change_op_open(const char *id, CK_SLOT_ID slot_id,
                                   const char *mode)
{
    char hsm_mk_change_file[PATH_MAX];
    FILE *fp;

    if (slot_id != (CK_SLOT_ID)-1) {
        if (ock_snprintf(hsm_mk_change_file, PATH_MAX, "%s/HSM_MK_CHANGE/%s-%lu",
                         CONFIG_PATH, id, slot_id) != 0) {
            TRACE_ERROR("HSM_MK_CHANGE directory path buffer overflow\n");
            return NULL;
        }
    } else {
        if (ock_snprintf(hsm_mk_change_file, PATH_MAX, "%s/HSM_MK_CHANGE/%s",
                         CONFIG_PATH, id) != 0) {
            TRACE_ERROR("HSM_MK_CHANGE directory path buffer overflow\n");
            return NULL;
        }
    }

    TRACE_DEVEL("file to open: %s mode: %s\n", hsm_mk_change_file, mode);

    fp = fopen(hsm_mk_change_file, mode);
    if (fp == NULL) {
        TRACE_ERROR("%s fopen(%s, %s): %s\n", __func__,
                        hsm_mk_change_file, mode, strerror(errno));
    }

    return fp;
}

CK_RV hsm_mk_change_op_save(const struct hsm_mk_change_op *op)
{
    struct hsm_mk_change_op_hdr *op_hdr;
    size_t info_len = 0, slots_len, len;
    unsigned char *buff = NULL;
    FILE *fp = NULL;
    CK_RV rc = CKR_OK;

    rc = hsm_mk_change_info_flatten(&op->info, NULL, &info_len);
    if (rc != CKR_OK)
        return rc;

    rc = hsm_mk_change_slots_flatten(op->slots, op->num_slots, NULL,
                                     &slots_len);
    if (rc != CKR_OK)
        return rc;

    len = sizeof(struct hsm_mk_change_op_hdr) + info_len + slots_len;

    buff = calloc(1, len);
    if (buff == NULL) {
        TRACE_ERROR("malloc failed\n");
        return CKR_HOST_MEMORY;
    }

    TRACE_DEBUG("Id: %s\n", op->id);
    TRACE_DEBUG("State: %d\n", op->state);
    op_hdr = (struct hsm_mk_change_op_hdr *)buff;
    memcpy(op_hdr->id, op->id, sizeof(op_hdr->id));
    op_hdr->state = htobe32(op->state);

    rc = hsm_mk_change_info_flatten(&op->info, buff + sizeof(*op_hdr),
                                    &info_len);
    if (rc != CKR_OK)
        goto out;

    rc = hsm_mk_change_slots_flatten(op->slots, op->num_slots,
                                     buff + sizeof(*op_hdr) + info_len,
                                     &slots_len);
    if (rc != CKR_OK)
        goto out;

    fp = hsm_mk_change_op_open(op->id, -1, "w");
    if (fp == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    hsm_mk_change_op_set_perm(fileno(fp));

    if (fwrite(buff, len, 1, fp) != 1) {
        TRACE_ERROR("fwrite(%s): %s\n", op->id, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

out:
    free(buff);
    if (fp != NULL)
        fclose(fp);
    return rc;
}

CK_RV hsm_mk_change_op_load(const char *id, struct hsm_mk_change_op *op)
{
    struct hsm_mk_change_op_hdr *op_hdr;
    struct stat sb;
    size_t len, info_read = 0, slots_read;
    FILE *fp;
    unsigned char *buff = NULL;
    CK_RV rc = CKR_OK;

    hsm_mk_change_op_clean(op);

    fp = hsm_mk_change_op_open(id, -1, "r");
    if (fp == NULL)
        return CKR_FUNCTION_FAILED;

    if (fstat(fileno(fp), &sb)) {
        TRACE_ERROR("fstat(%s): %s\n", op->id, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    len = sb.st_size;
    buff = calloc(1, len);
    if (buff == NULL) {
        TRACE_ERROR("malloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (fread(buff, len, 1, fp) != 1) {
        TRACE_ERROR("fread(%s): %s\n", op->id, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    op_hdr = (struct hsm_mk_change_op_hdr *)buff;
    memcpy(op->id, op_hdr->id, sizeof(op_hdr->id));
    op->state = htobe32(op_hdr->state);
    len -= sizeof(*op_hdr);

    TRACE_DEBUG("Id: %s\n", op->id);
    TRACE_DEBUG("State: %d\n", op->state);

    rc = hsm_mk_change_info_unflatten(buff + sizeof(*op_hdr), len, &info_read,
                                      &op->info);
    if (rc != CKR_OK)
        goto out;

    rc = hsm_mk_change_slots_unflatten(buff + sizeof(*op_hdr) + info_read,
                                       len - info_read, &slots_read,
                                       &op->slots, &op->num_slots);
    if (rc != CKR_OK)
        goto out;

    if (info_read + slots_read != len) {
        TRACE_ERROR("Not all data read for file %s: len: %lu read: %lu\n",
                    op->id, len, info_read + slots_read);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

out:
    if (rc != CKR_OK)
        hsm_mk_change_op_clean(op);

    if (buff != NULL)
        free(buff);
    fclose(fp);
    return rc;
}

CK_RV hsm_mk_change_op_create(struct hsm_mk_change_op *op)
{
    char hsm_mk_change_file[PATH_MAX];
    int fd;
    CK_RV rc;

    if (ock_snprintf(hsm_mk_change_file, PATH_MAX, "%s/HSM_MK_CHANGE/XXXXXX",
                     CONFIG_PATH) != 0) {
        TRACE_ERROR("HSM_MK_CHANGE directory path buffer overflow\n");
        return CKR_FUNCTION_FAILED;
    }

    fd = mkstemp(hsm_mk_change_file);
    if (fd < 0) {
        TRACE_ERROR("mkstemp(%s) failed with: %s\n", hsm_mk_change_file,
                    strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    close(fd); /* written and permissions set by hsm_mk_change_op_save */

    TRACE_DEVEL("created file: %s\n", hsm_mk_change_file);

    memcpy(op->id, &hsm_mk_change_file[strlen(hsm_mk_change_file) - 6], 6);

    rc = hsm_mk_change_op_save(op);

out:
    return rc;
}

CK_RV hsm_mk_change_token_mkvps_save(const char *id, CK_SLOT_ID slot_id,
                                     const struct hsm_mkvp *mkvps,
                                     unsigned int num_mkvps)
{
    size_t len = 0;
    unsigned char *buff = NULL;
    FILE *fp = NULL;
    CK_RV rc = CKR_OK;

    rc = hsm_mk_change_mkvps_flatten(mkvps, num_mkvps, NULL, &len);
    if (rc != CKR_OK)
        return rc;

    buff = calloc(1, len);
    if (buff == NULL) {
        TRACE_ERROR("malloc failed\n");
        return CKR_HOST_MEMORY;
    }

    rc = hsm_mk_change_mkvps_flatten(mkvps, num_mkvps, buff, &len);
    if (rc != CKR_OK)
        goto out;

    fp = hsm_mk_change_op_open(id, slot_id, "w");
    if (fp == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    hsm_mk_change_op_set_perm(fileno(fp));

    if (fwrite(buff, len, 1, fp) != 1) {
        TRACE_ERROR("fwrite(%s-%lu): %s\n", id, slot_id, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

out:
    free(buff);
    if (fp != NULL)
        fclose(fp);
    return rc;
}

CK_RV hsm_mk_change_token_mkvps_load(const char *id, CK_SLOT_ID slot_id,
                                     struct hsm_mkvp **mkvps,
                                     unsigned int *num_mkvps)
{
    struct stat sb;
    size_t len, read = 0;
    FILE *fp;
    unsigned char *buff = NULL;
    CK_RV rc = CKR_OK;

    fp = hsm_mk_change_op_open(id, slot_id, "r");
    if (fp == NULL)
        return CKR_FUNCTION_FAILED;

    if (fstat(fileno(fp), &sb)) {
        TRACE_ERROR("fstat(%s-%lu): %s\n", id, slot_id, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    len = sb.st_size;
    buff = calloc(1, len);
    if (buff == NULL) {
        TRACE_ERROR("malloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (fread(buff, len, 1, fp) != 1) {
        TRACE_ERROR("fread(%s-%lu): %s\n", id, slot_id, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = hsm_mk_change_mkvps_unflatten(buff, len, &read, mkvps, num_mkvps);
    if (rc != CKR_OK)
        goto out;

    if (read != len) {
        TRACE_ERROR("Not all datta read for file %s-%lu: len: %lu read: %lu\n",
                    id, slot_id, len, read);
        rc = CKR_FUNCTION_FAILED;
        hsm_mk_change_mkvps_clean(*mkvps, *num_mkvps);
        goto out;
    }

out:
    if (buff != NULL)
        free(buff);
    fclose(fp);
    return rc;
}

CK_RV hsm_mk_change_op_remove(const char *id)
{
    char hsm_mk_change_dir[PATH_MAX];
    char hsm_mk_change_file[PATH_MAX];
    struct dirent **namelist;
    CK_RV rc = CKR_OK;
    int n, i;

    if (ock_snprintf(hsm_mk_change_dir, PATH_MAX, "%s/HSM_MK_CHANGE",
                     CONFIG_PATH) != 0) {
        TRACE_ERROR("HSM_MK_CHANGE directory path buffer overflow\n");
        return CKR_FUNCTION_FAILED;
    }

    n = scandir(hsm_mk_change_dir, &namelist, NULL, alphasort);
    if (n == -1) {
        TRACE_ERROR("scandir(%s) failed with: %s\n", hsm_mk_change_dir,
                    strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    for (i = 0; i < n ; i++) {
        if (namelist[i]->d_name[0] == '.')
            continue;
        if (strncmp(namelist[i]->d_name, id, strlen(id)) != 0)
            continue;

        if (ock_snprintf(hsm_mk_change_file, PATH_MAX, "%s/HSM_MK_CHANGE/%s",
                         CONFIG_PATH, namelist[i]->d_name) != 0) {
            TRACE_ERROR("HSM_MK_CHANGE file path buffer overflow\n");
            rc = CKR_FUNCTION_FAILED;
            break;
        }

        TRACE_DEVEL("remove %s\n", hsm_mk_change_file);

        if (remove(hsm_mk_change_file) != 0) {
            TRACE_ERROR("remove(%s) failed with: %s\n", hsm_mk_change_file,
                        strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            break;
        }
    }

    for (i = 0; i < n ; i++)
            free(namelist[i]);
    free(namelist);

    return rc;
}

CK_RV hsm_mk_change_op_iterate(CK_RV (*cb)(struct hsm_mk_change_op *op,
                                           void *private), void *private)
{
    struct hsm_mk_change_op op;
    char hsm_mk_change_dir[PATH_MAX];
    struct dirent **namelist;
    CK_RV rc = CKR_OK;
    int n, i;

    if (ock_snprintf(hsm_mk_change_dir, PATH_MAX, "%s/HSM_MK_CHANGE",
                     CONFIG_PATH) != 0) {
        TRACE_ERROR("HSM_MK_CHANGE directory path buffer overflow\n");
        return CKR_FUNCTION_FAILED;
    }

    memset(&op, 0, sizeof(op));

    n = scandir(hsm_mk_change_dir, &namelist, NULL, alphasort);
    if (n == -1) {
        TRACE_ERROR("scandir(%s) failed with: %s\n", hsm_mk_change_dir,
                    strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    for (i = 0; i < n ; i++) {
        if (namelist[i]->d_name[0] == '.')
            continue;
        if (strlen(namelist[i]->d_name) > 6 && namelist[i]->d_name[6] == '-')
            continue;

        rc = hsm_mk_change_op_load(namelist[i]->d_name,  &op);
        if (rc != CKR_OK)
            break;

        rc = cb(&op, private);
        hsm_mk_change_op_clean(&op);
        if (rc != CKR_OK)
            break;
    }

    for (i = 0; i < n ; i++)
            free(namelist[i]);
    free(namelist);

    return rc;
}

