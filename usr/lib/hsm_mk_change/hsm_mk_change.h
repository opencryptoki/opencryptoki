/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef HSM_MK_CHANGE_H
#define HSM_MK_CHANGE_H

enum hsm_mk_change_state {
    HSM_MK_CH_STATE_INITIAL = 0,
    HSM_MK_CH_STATE_REENCIPHERING = 10, /* Tokens are reenciphering the keys */
    HSM_MK_CH_STATE_REENCIPHERED = 11, /* Keys are reenciphered */
    HSM_MK_CH_STATE_FINALIZING = 20, /* Tokens are finalizing the MK change */
    HSM_MK_CH_STATE_CANCELING = 30, /* Tokens are canceling the MK change */
    HSM_MK_CH_STATE_ERROR = 100,
};

struct apqn {
    unsigned short card;
    unsigned short domain;
};

enum hsm_mk_type {
    HSM_MK_TYPE_EP11 = 1,
    HSM_MK_TYPE_CCA_SYM = 2,
    HSM_MK_TYPE_CCA_ASYM = 3,
    HSM_MK_TYPE_CCA_AES = 4,
    HSM_MK_TYPE_CCA_APKA = 5,
};

#define HSM_MK_TYPE_MAX     HSM_MK_TYPE_CCA_APKA

struct hsm_mkvp {
    enum hsm_mk_type type;
    unsigned int mkvp_len;
    unsigned char *mkvp;
};

struct hsm_mk_change_info {
    unsigned int num_apqns;
    struct apqn *apqns;
    unsigned int num_mkvps;
    struct hsm_mkvp *mkvps;
};

struct hsm_mk_change_op {
    char id[7];
    enum hsm_mk_change_state state;
    struct hsm_mk_change_info info;
    CK_SLOT_ID *slots;
    unsigned int num_slots;
};

CK_RV hsm_mk_change_apqns_flatten(const struct apqn *apqns,
                                  unsigned int num_apqns, unsigned char *buff,
                                  size_t *buff_len);
CK_RV hsm_mk_change_apqns_unflatten(const unsigned char *buff, size_t buff_len,
                                    size_t *bytes_read, struct apqn **apqns,
                                    unsigned int *num_apqns);
int hsm_mk_change_apqns_find(const struct apqn *apqns, unsigned int num_apqns,
                             unsigned short card, unsigned short domain);

void hsm_mk_change_mkvps_clean(struct hsm_mkvp *mkvps, unsigned int num_mkvps);
CK_RV hsm_mk_change_mkvps_flatten(const struct hsm_mkvp *mkvps,
                                  unsigned int num_mkvps, unsigned char *buff,
                                  size_t *buff_len);
CK_RV hsm_mk_change_mkvps_unflatten(const unsigned char *buff, size_t buff_len,
                                    size_t *bytes_read, struct hsm_mkvp **mkvps,
                                    unsigned int *num_mkvps);
const unsigned char *hsm_mk_change_mkvps_find(const struct hsm_mkvp *mkvps,
                                              unsigned int num_mkvps,
                                              enum hsm_mk_type type,
                                              unsigned int mkvp_len);

void hsm_mk_change_info_clean(struct hsm_mk_change_info *info);
CK_RV hsm_mk_change_info_flatten(const struct hsm_mk_change_info *info,
                                 unsigned char *buff, size_t *buff_len);
CK_RV hsm_mk_change_info_unflatten(const unsigned char *buff, size_t buff_len,
                                   size_t *bytes_read,
                                   struct hsm_mk_change_info *info);

CK_RV hsm_mk_change_slots_flatten(const CK_SLOT_ID *slots,
                                  unsigned int num_slots, unsigned char *buff,
                                  size_t *buff_len);
CK_RV hsm_mk_change_slots_unflatten(const unsigned char *buff, size_t buff_len,
                                    size_t *bytes_read, CK_SLOT_ID **slots,
                                    unsigned int *num_slots);

void hsm_mk_change_op_clean(struct hsm_mk_change_op *op);
CK_RV hsm_mk_change_op_save(const struct hsm_mk_change_op *op);
CK_RV hsm_mk_change_op_load(const char *id, struct hsm_mk_change_op *op);
CK_RV hsm_mk_change_op_create(struct hsm_mk_change_op *op);
CK_RV hsm_mk_change_op_remove(const char *id);
CK_RV hsm_mk_change_op_iterate(CK_RV (*cb)(struct hsm_mk_change_op *op,
                                           void *private), void *private);

CK_RV hsm_mk_change_token_mkvps_save(const char *id, CK_SLOT_ID slot_id,
                                     const struct hsm_mkvp *mkvps,
                                     unsigned int num_mkvps);
CK_RV hsm_mk_change_token_mkvps_load(const char *id, CK_SLOT_ID slot_id,
                                     struct hsm_mkvp **mkvps,
                                     unsigned int *num_mkvps);

CK_RV hsm_mk_change_lock_create(void);
void hsm_mk_change_lock_destroy(void);
CK_RV hsm_mk_change_lock(int exclusive);
CK_RV hsm_mk_change_unlock(void);


#endif
