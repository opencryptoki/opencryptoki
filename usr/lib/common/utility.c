/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "p11util.h"
#include "attributes.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "shared_memory.h"
#include "trace.h"
#include "ock_syslog.h"
#include "slotmgr.h" // for ock_snprintf

#include <sys/file.h>
#include <syslog.h>

CK_RV CreateXProcLock(char *tokname, STDLL_TokData_t *tokdata)
{
    char lockfile[PATH_MAX];
    char lockdir[PATH_MAX];
    struct group *grp;
    struct stat statbuf;
    int ret = -1;
    char *toklockname;

    if (tokdata->spinxplfd == -1) {

        if (token_specific.t_creatlock != NULL) {
            tokdata->spinxplfd = token_specific.t_creatlock();
            if (tokdata->spinxplfd != -1)
                return CKR_OK;
            else
                return CKR_FUNCTION_FAILED;
        }

        toklockname = (strlen(tokname) > 0) ? tokname : SUB_DIR;

        /** create lock subdir for each token if it doesn't exist.
         *  The root directory should be created in slotmgr daemon **/
        if (ock_snprintf(lockdir, PATH_MAX, "%s/%s",
                         LOCKDIR_PATH, toklockname) != 0) {
            OCK_SYSLOG(LOG_ERR, "lock directory path too long\n");
            TRACE_ERROR("lock directory path too long\n");
            goto err;
        }

        ret = stat(lockdir, &statbuf);
        if (ret != 0 && errno == ENOENT) {
            /* dir does not exist, try to create it */
            ret = mkdir(lockdir, S_IRWXU | S_IRWXG);
            if (ret != 0) {
                OCK_SYSLOG(LOG_ERR,
                           "Directory(%s) missing: %s\n",
                           lockdir, strerror(errno));
                goto err;
            }
            grp = getgrnam(PKCS_GROUP);
            if (grp == NULL) {
                fprintf(stderr, "getgrname(%s): %s", PKCS_GROUP,
                        strerror(errno));
                goto err;
            }
            /* set ownership to euid, and pkcs11 group */
            if (chown(lockdir, geteuid(), grp->gr_gid) != 0) {
                fprintf(stderr, "Failed to set owner:group \
                        ownership on %s directory", lockdir);
                goto err;
            }
            /* mkdir does not set group permission right, so
             ** trying explictly here again */
            if (chmod(lockdir, S_IRWXU | S_IRWXG) != 0) {
                fprintf(stderr, "Failed to change \
                        permissions on %s directory", lockdir);
                goto err;
            }
        }

        /* create user lock file */
        if (ock_snprintf(lockfile, sizeof(lockfile), "%s/%s/LCK..%s",
                         LOCKDIR_PATH, toklockname, toklockname) != 0) {
            OCK_SYSLOG(LOG_ERR, "lock file path too long\n");
            TRACE_ERROR("lock file path too long\n");
            goto err;
        }

        if (stat(lockfile, &statbuf) == 0) {
            tokdata->spinxplfd = open(lockfile, OPEN_MODE);
        } else {
            tokdata->spinxplfd = open(lockfile, O_CREAT | OPEN_MODE, MODE_BITS);
            if (tokdata->spinxplfd != -1) {
                /* umask may prevent correct mode, so set it. */
                if (fchmod(tokdata->spinxplfd, MODE_BITS) == -1) {
                    OCK_SYSLOG(LOG_ERR, "fchmod(%s): %s\n",
                               lockfile, strerror(errno));
                    goto err;
                }

                grp = getgrnam(PKCS_GROUP);
                if (grp != NULL) {
                    if (fchown(tokdata->spinxplfd, -1, grp->gr_gid) == -1) {
                        OCK_SYSLOG(LOG_ERR,
                                   "fchown(%s): %s\n",
                                   lockfile, strerror(errno));
                        goto err;
                    }
                } else {
                    OCK_SYSLOG(LOG_ERR, "getgrnam(): %s\n", strerror(errno));
                    goto err;
                }
            }
        }
        if (tokdata->spinxplfd == -1) {
            OCK_SYSLOG(LOG_ERR, "open(%s): %s\n", lockfile, strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }

    return CKR_OK;

err:
    if (tokdata->spinxplfd != -1)
        close(tokdata->spinxplfd);

    return CKR_FUNCTION_FAILED;
}

void CloseXProcLock(STDLL_TokData_t *tokdata)
{
    if (tokdata->spinxplfd != -1)
        close(tokdata->spinxplfd);
    pthread_mutex_destroy(&tokdata->spinxplfd_mutex);
}

CK_RV XThreadLock(STDLL_TokData_t *tokdata)
{
    if (pthread_mutex_lock(&tokdata->spinxplfd_mutex)) {
        TRACE_ERROR("Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV XThreadUnLock(STDLL_TokData_t *tokdata)
{
    if (pthread_mutex_unlock(&tokdata->spinxplfd_mutex)) {
        TRACE_ERROR("Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV XProcLock(STDLL_TokData_t *tokdata)
{
    if (XThreadLock(tokdata) != CKR_OK)
        return CKR_CANT_LOCK;

    if (tokdata->spinxplfd < 0)  {
        TRACE_DEVEL("No file descriptor to lock with.\n");
        pthread_mutex_unlock(&tokdata->spinxplfd_mutex);
        return CKR_CANT_LOCK;
    }

    if (tokdata->spinxplfd_count == 0) {
        if (flock(tokdata->spinxplfd, LOCK_EX) != 0) {
            TRACE_DEVEL("flock has failed.\n");
            pthread_mutex_unlock(&tokdata->spinxplfd_mutex);
            return CKR_CANT_LOCK;
        }
    }
    tokdata->spinxplfd_count++;

    return CKR_OK;
}

CK_RV XProcUnLock(STDLL_TokData_t *tokdata)
{
    if (tokdata->spinxplfd < 0)  {
        TRACE_DEVEL("No file descriptor to unlock with.\n");
        return CKR_CANT_LOCK;
    }

    if (tokdata->spinxplfd_count == 0) {
        TRACE_DEVEL("No file lock is held.\n");
        return CKR_CANT_LOCK;
    }
    if (tokdata->spinxplfd_count == 1) {
        if (flock(tokdata->spinxplfd, LOCK_UN) != 0) {
            TRACE_DEVEL("flock has failed.\n");
            return CKR_CANT_LOCK;
        }
    }
    tokdata->spinxplfd_count--;

    if (XThreadUnLock(tokdata) != CKR_OK)
        return CKR_CANT_LOCK;

    return CKR_OK;
}

CK_RV XProcLock_Init(STDLL_TokData_t *tokdata)
{
    pthread_mutexattr_t attr;

    tokdata->spinxplfd = -1;
    tokdata->spinxplfd_count = 0;

    if (pthread_mutexattr_init(&attr)) {
        TRACE_ERROR("Mutex attribute init failed.\n");
        return CKR_CANT_LOCK;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
        TRACE_ERROR("Mutex attribute set failed.\n");
        return CKR_CANT_LOCK;
    }
    if (pthread_mutex_init(&tokdata->spinxplfd_mutex, &attr)) {
        TRACE_ERROR("Mutex init failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

//
//

extern const char manuf[];
extern const char model[];
extern const char descr[];
extern const char label[];

//
//
void init_slotInfo(CK_SLOT_INFO *slot_info)
{
    memset(slot_info->slotDescription, ' ', sizeof(slot_info->slotDescription));
    memset(slot_info->manufacturerID, ' ', sizeof(slot_info->manufacturerID));

    memcpy(slot_info->slotDescription, descr, strlen(descr));
    memcpy(slot_info->manufacturerID, manuf, strlen(manuf));

    slot_info->hardwareVersion.major = 1;
    slot_info->hardwareVersion.minor = 0;
    slot_info->firmwareVersion.major = 1;
    slot_info->firmwareVersion.minor = 0;
    slot_info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
}

//
//
void init_tokenInfo(TOKEN_DATA *nv_token_data)
{
    CK_TOKEN_INFO_32 *token_info = &nv_token_data->token_info;

    memset(token_info->label, ' ', sizeof(token_info->label));
    memset(token_info->manufacturerID, ' ', sizeof(token_info->manufacturerID));
    memset(token_info->model, ' ', sizeof(token_info->model));
    memset(token_info->serialNumber, ' ', sizeof(token_info->serialNumber));
    memset(token_info->utcTime, ' ', sizeof(token_info->utcTime));

    memcpy(token_info->label, label, strlen(label));
    memcpy(token_info->manufacturerID, manuf, strlen(manuf));
    memcpy(token_info->model, model, strlen(model));

    // Unused
    // memcpy(token_info->serialNumber, "123", 3);

    // I don't see any API support for changing the clock so
    // we will use the system clock for the token's clock.
    //

    token_info->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_CLOCK_ON_TOKEN |
        CKF_SO_PIN_TO_BE_CHANGED | CKF_USER_PIN_TO_BE_CHANGED |
        CKF_DUAL_CRYPTO_OPERATIONS;

    // For the release, we made these
    // values as CK_UNAVAILABLE_INFORMATION or CK_EFFECTIVELY_INFINITE
    //
    token_info->ulMaxSessionCount = (CK_ULONG_32) CK_EFFECTIVELY_INFINITE;
    token_info->ulSessionCount = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
    token_info->ulMaxRwSessionCount = (CK_ULONG_32) CK_EFFECTIVELY_INFINITE;
    token_info->ulRwSessionCount = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
    token_info->ulMaxPinLen = MAX_PIN_LEN;
    token_info->ulMinPinLen = MIN_PIN_LEN;
    token_info->ulTotalPublicMemory = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
    token_info->ulFreePublicMemory = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
    token_info->ulTotalPrivateMemory = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
    token_info->ulFreePrivateMemory = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;

    token_info->hardwareVersion.major = 0;
    token_info->hardwareVersion.minor = 0;
    token_info->firmwareVersion.major = 0;
    token_info->firmwareVersion.minor = 0;
}

//
//
CK_RV init_token_data(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
    CK_RV rc;
    TOKEN_DATA_VERSION *dat = &tokdata->nv_token_data->dat;

    memset((char *) tokdata->nv_token_data, 0, sizeof(TOKEN_DATA));

    // the normal USER pin is not set when the token is initialized
    //
    if (tokdata->version < TOK_NEW_DATA_STORE) {
        memcpy(tokdata->nv_token_data->user_pin_sha, "00000000000000000000",
               SHA1_HASH_SIZE);
        memcpy(tokdata->nv_token_data->so_pin_sha, default_so_pin_sha,
               SHA1_HASH_SIZE);

        memset(tokdata->user_pin_md5, 0x0, MD5_HASH_SIZE);
        memcpy(tokdata->so_pin_md5, default_so_pin_md5, MD5_HASH_SIZE);
    } else {
        dat->version = tokdata->version;

        /* SO login key */
        dat->so_login_it = SO_KDF_LOGIN_IT;
        memcpy(dat->so_login_salt, SO_KDF_LOGIN_PURPOSE, 32);
        rng_generate(tokdata, dat->so_login_salt + 32, 32);

        rc = compute_PKCS5_PBKDF2_HMAC(tokdata, (CK_BYTE *)SO_PIN_DEFAULT,
                                       strlen(SO_PIN_DEFAULT),
                                       dat->so_login_salt, 64,
                                       dat->so_login_it, EVP_sha512(),
                                       256 / 8, dat->so_login_key);
        if (rc != CKR_OK) {
            TRACE_DEVEL("PBKDF2 failed.\n");
            return rc;
        }

        /* SO wrap key */
        dat->so_wrap_it = SO_KDF_WRAP_IT;
        memcpy(dat->so_wrap_salt, SO_KDF_WRAP_PURPOSE, 32);
        rng_generate(tokdata, dat->so_wrap_salt + 32, 32);

        rc = compute_PKCS5_PBKDF2_HMAC(tokdata, (CK_BYTE *)SO_PIN_DEFAULT,
                                       strlen(SO_PIN_DEFAULT),
                                       dat->so_wrap_salt, 64,
                                       dat->so_wrap_it, EVP_sha512(),
                                       256 / 8, tokdata->so_wrap_key);
        if (rc != CKR_OK) {
            TRACE_DEVEL("PBKDF2 failed.\n");
            return rc;
        }

        /* User login key */
        dat->user_login_it = USER_KDF_LOGIN_IT;
        memcpy(dat->user_login_salt, USER_KDF_LOGIN_PURPOSE, 32);
        rng_generate(tokdata, dat->user_login_salt + 32, 32);

        rc = compute_PKCS5_PBKDF2_HMAC(tokdata, (CK_BYTE *)USER_PIN_DEFAULT,
                                       strlen(USER_PIN_DEFAULT),
                                       dat->user_login_salt, 64,
                                       dat->user_login_it, EVP_sha512(),
                                       256 / 8, dat->user_login_key);
        if (rc != CKR_OK) {
            TRACE_DEVEL("PBKDF2 failed.\n");
            return rc;
        }

        /* User wrap key */
        dat->user_wrap_it = USER_KDF_WRAP_IT;
        memcpy(dat->user_wrap_salt, USER_KDF_WRAP_PURPOSE, 32);
        rng_generate(tokdata, dat->user_wrap_salt + 32, 32);

        rc = compute_PKCS5_PBKDF2_HMAC(tokdata, (CK_BYTE *)USER_PIN_DEFAULT,
                                       strlen(USER_PIN_DEFAULT),
                                       dat->user_wrap_salt, 64,
                                       dat->user_wrap_it, EVP_sha512(),
                                       256 / 8, tokdata->user_wrap_key);
        if (rc != CKR_OK) {
            TRACE_DEVEL("PBKDF2 failed.\n");
            return rc;
        }
    }

    // generate the master key used for signing the Operation State information
    //                          `
    memset(tokdata->nv_token_data->token_info.label, ' ',
           sizeof(tokdata->nv_token_data->token_info.label));
    memcpy(tokdata->nv_token_data->token_info.label, label,
           strlen(label));

    tokdata->nv_token_data->tweak_vector.allow_weak_des = TRUE;
    tokdata->nv_token_data->tweak_vector.check_des_parity = FALSE;
    tokdata->nv_token_data->tweak_vector.allow_key_mods = TRUE;
    tokdata->nv_token_data->tweak_vector.netscape_mods = TRUE;

    init_tokenInfo(tokdata->nv_token_data);

    if (token_specific.t_init_token_data) {
        rc = token_specific.t_init_token_data(tokdata, slot_id);
        if (rc != CKR_OK)
            return rc;
    } else {
        //
        // FIXME: erase the token object index file (and all token objects)
        //
        rc = generate_master_key(tokdata, tokdata->master_key);
        if (rc != CKR_OK) {
            TRACE_DEVEL("generate_master_key failed.\n");
            return CKR_FUNCTION_FAILED;
        }

        rc = save_masterkey_so(tokdata);
        if (rc != CKR_OK) {
            TRACE_DEVEL("save_masterkey_so failed.\n");
            return rc;
        }
    }

    rc = save_token_data(tokdata, slot_id);

    return rc;
}

//
//
CK_RV build_attribute(CK_ATTRIBUTE_TYPE type,
                      CK_BYTE *data, CK_ULONG data_len, CK_ATTRIBUTE **attrib)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + data_len);
    if (!attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    attr->type = type;
    attr->ulValueLen = data_len;

    if (data_len > 0) {
        attr->pValue = (CK_BYTE *) attr + sizeof(CK_ATTRIBUTE);
        if (is_attribute_attr_array(type)) {
            rc = dup_attribute_array_no_alloc((CK_ATTRIBUTE_PTR)data,
                                               data_len / sizeof(CK_ATTRIBUTE),
                                               (CK_ATTRIBUTE_PTR)attr->pValue);
            if (rc != CKR_OK) {
                TRACE_ERROR("dup_attribute_array_no_alloc failed\n");
                free(attr);
                return rc;
            }
        } else {
            memcpy(attr->pValue, data, data_len);
        }
    } else {
        attr->pValue = NULL;
    }

    *attrib = attr;

    return CKR_OK;
}

/*
 * Find an attribute in an attribute array.
 *
 * Returns CKR_FUNCTION_FAILED when attribute is not found,
 * CKR_ATTRIBUTE_TYPE_INVALID when length doesn't match the expected and
 * CKR_OK when values is returned in the `value` argument.
 */
CK_RV find_bbool_attribute(CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
                           CK_ATTRIBUTE_TYPE type, CK_BBOOL *value)
{
    CK_ULONG i;

    for (i = 0; i < attrs_len; i++) {
        if (attrs[i].type == type) {
            /* Check size */
            if (attrs[i].ulValueLen != sizeof(*value) ||
                attrs[i].pValue == NULL)
                return CKR_ATTRIBUTE_VALUE_INVALID;

            /* Get value */
            *value = *((CK_BBOOL *) attrs[i].pValue);
        }
    }

    return CKR_FUNCTION_FAILED;
}

//
//
CK_RV add_pkcs_padding(CK_BYTE *ptr,
                       CK_ULONG block_size, CK_ULONG data_len,
                       CK_ULONG total_len)
{
    CK_ULONG i, pad_len;
    CK_BYTE pad_value;

    pad_len = block_size - (data_len % block_size);
    pad_value = (CK_BYTE) pad_len;

    if (data_len + pad_len > total_len) {
        TRACE_ERROR("The total length is too small to add padding.\n");
        return CKR_FUNCTION_FAILED;
    }
    for (i = 0; i < pad_len; i++)
        ptr[i] = pad_value;

    return CKR_OK;
}

//
//
CK_RV strip_pkcs_padding(CK_BYTE *ptr, CK_ULONG total_len, CK_ULONG *data_len)
{
    CK_BYTE pad_value;

    pad_value = ptr[total_len - 1];
    if (pad_value > total_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
        return CKR_ENCRYPTED_DATA_INVALID;
    }
    // thus, we have 'pad_value' bytes of 'pad_value' appended to the end
    //
    *data_len = total_len - pad_value;

    return CKR_OK;
}

//
//
CK_BYTE parity_adjust(CK_BYTE b)
{
    if (parity_is_odd(b) == FALSE)
        b = (b & 0xFE) | ((~b) & 0x1);

    return b;
}

//
//
CK_RV parity_is_odd(CK_BYTE b)
{
    b = ((b >> 4) ^ b) & 0x0f;
    b = ((b >> 2) ^ b) & 0x03;
    b = ((b >> 1) ^ b) & 0x01;

    if (b == 1)
        return TRUE;
    else
        return FALSE;
}

CK_RV attach_shm(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
    CK_RV rc;
    int ret;
    char buf[PATH_MAX];
    LW_SHM_TYPE **shm = &tokdata->global_shm;

    if (token_specific.t_attach_shm != NULL)
        return token_specific.t_attach_shm(tokdata, slot_id);

    rc = XProcLock(tokdata);
    if (rc != CKR_OK)
        return rc;

    /*
     * Attach to an existing shared memory region or create it if it doesn't
     * exists. When it's created (ret=0) the region is initialized with
     * zeros.
     */
    if (get_pk_dir(tokdata, buf, PATH_MAX) == NULL) {
        TRACE_ERROR("pk_dir buffer overflow");
        rc = CKR_FUNCTION_FAILED;
        goto err;
    }
    ret = sm_open(buf, 0660, (void **) shm, sizeof(**shm), 0);
    if (ret < 0) {
        TRACE_DEVEL("sm_open failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto err;
    }

    return XProcUnLock(tokdata);

err:
    XProcUnLock(tokdata);
    return rc;
}

CK_RV detach_shm(STDLL_TokData_t *tokdata, CK_BBOOL ignore_ref_count)
{
    CK_RV rc;

    rc = XProcLock(tokdata);
    if (rc != CKR_OK)
        return rc;

    if (sm_close((void *) tokdata->global_shm, 0, ignore_ref_count)) {
        TRACE_DEVEL("sm_close failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto err;
    }

    return XProcUnLock(tokdata);

err:
    XProcUnLock(tokdata);
    return rc;
}

/* Compute specified SHA or MD5 using software */
CK_RV compute_sha(STDLL_TokData_t *tokdata, CK_BYTE *data, CK_ULONG len,
                  CK_BYTE *hash, CK_ULONG mech)
{
    const EVP_MD *md;
    unsigned int hash_len;

    UNUSED(tokdata);

    switch (mech) {
    case CKM_MD5:
        hash_len = MD5_HASH_SIZE;
        md = EVP_md5();
        break;
    case CKM_SHA_1:
        hash_len = SHA1_HASH_SIZE;
        md = EVP_sha1();
        break;
    case CKM_SHA224:
    case CKM_SHA512_224:
        hash_len = SHA224_HASH_SIZE;
        md = EVP_sha224();
        break;
    case CKM_SHA256:
    case CKM_SHA512_256:
        hash_len = SHA256_HASH_SIZE;
        md = EVP_sha256();
        break;
    case CKM_SHA384:
        hash_len = SHA384_HASH_SIZE;
        md = EVP_sha384();
        break;
    case CKM_SHA512:
        hash_len = SHA512_HASH_SIZE;
        md = EVP_sha512();
        break;
#ifdef NID_sha3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        hash_len = SHA3_224_HASH_SIZE;
        md = EVP_sha3_224();
        break;
#endif
#ifdef NID_sha3_256
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        hash_len = SHA3_256_HASH_SIZE;
        md = EVP_sha3_256();
        break;
#endif
#ifdef NID_sha3_384
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        hash_len = SHA3_384_HASH_SIZE;
        md = EVP_sha3_384();
        break;
#endif
#ifdef NID_sha3_512
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        hash_len = SHA3_512_HASH_SIZE;
        md = EVP_sha3_512();
        break;
#endif
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (EVP_Digest(data, len, hash, &hash_len, md, NULL) != 1) {
        TRACE_ERROR("%s EVP_Digest failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/* Compute SHA1 using software implementation */
CK_RV compute_sha1(STDLL_TokData_t *tokdata, CK_BYTE *data, CK_ULONG len,
                   CK_BYTE *hash)
{
    CK_RV rc;
    const CK_MECHANISM mech = { CKM_SHA_1, NULL, 0 };

    rc = compute_sha(tokdata, data, len, hash, CKM_SHA_1);

    if (rc == CKR_OK &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id, &mech,
                                            POLICY_STRENGTH_IDX_0);

    return rc;
}

CK_RV compute_md5(STDLL_TokData_t *tokdata, CK_BYTE *data, CK_ULONG len,
                  CK_BYTE *hash)
{
    CK_RV rc;
    const CK_MECHANISM mech = { CKM_MD5, NULL, 0 };

    rc = compute_sha(tokdata, data, len, hash, CKM_MD5);

    if (rc == CKR_OK &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id, &mech,
                                            POLICY_STRENGTH_IDX_0);

    return rc;
}

CK_RV compute_PKCS5_PBKDF2_HMAC(STDLL_TokData_t *tokdata,
                                CK_CHAR *pPin, CK_ULONG ulPinLen,
                                CK_BYTE *salt, CK_ULONG salt_len,
                                CK_ULONG it_count, const EVP_MD *digest,
                                CK_ULONG key_len, CK_BYTE *key)
{
    CK_RV rc = CKR_OK;
    const CK_MECHANISM mech = { CKM_PKCS5_PBKD2, NULL, 0 };
    CK_MECHANISM mech2 = { 0, NULL, 0 };

    if (PKCS5_PBKDF2_HMAC((char *)pPin, ulPinLen, salt, salt_len,
                          it_count, digest, key_len, key) != 1) {
        TRACE_DEVEL("PKCS5_PBKDF2_HMAC failed.\n");
        rc = CKR_FUNCTION_FAILED;
    }

    if (rc == CKR_OK &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0) {
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id, &mech,
                                            POLICY_STRENGTH_IDX_0);
        if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_IMPLICIT) != 0) {
            /* We use CKM_PKCS5_PBKD2 with CKP_PKCS5_PBKD2_HMAC_SHAxxx */
            switch (EVP_MD_type(digest)) {
            case NID_sha1:
                mech2.mechanism = CKM_SHA_1_HMAC;
                break;
            case NID_sha224:
                mech2.mechanism = CKM_SHA224_HMAC;
                break;
            case NID_sha256:
                mech2.mechanism = CKM_SHA256_HMAC;
                break;
            case NID_sha384:
                mech2.mechanism = CKM_SHA384_HMAC;
                break;
            case NID_sha512:
                mech2.mechanism = CKM_SHA512_HMAC;
                break;
            default:
                return rc;
            }
            /*
             * Use strength 0 because the HMAC key is the pin, and it is max
             * 8 char (i.e. 64 bit) long, which is way below 112 bit anyway.
             */
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id, &mech2,
                                                POLICY_STRENGTH_IDX_0);
        }
    }

    return rc;
}




CK_RV get_keytype(STDLL_TokData_t *tokdata, CK_OBJECT_HANDLE hkey,
                  CK_KEY_TYPE *keytype)
{
    CK_RV rc;
    OBJECT *key_obj = NULL;

    rc = object_mgr_find_in_map1(tokdata, hkey, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
        return rc;
    }

    rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                      keytype);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV pkcs_get_keytype(CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
                       CK_MECHANISM_PTR mech, CK_ULONG *type, CK_ULONG *class)
{
    CK_RV rc;

    *type = 0;
    *class = 0;

    rc = get_ulong_attribute_by_type(attrs, attrs_len, CKA_CLASS, class);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    rc = get_ulong_attribute_by_type(attrs, attrs_len, CKA_KEY_TYPE, type);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (rc == CKR_OK)
        return CKR_OK;

    /* no CKA_KEY_TYPE found, derive from mech */
    switch (mech->mechanism) {
    case CKM_DES_KEY_GEN:
        *type = CKK_DES;
        break;
    case CKM_DES2_KEY_GEN:
    case CKM_PBE_SHA1_DES2_EDE_CBC:
        *type = CKK_DES2;
        break;
    case CKM_DES3_KEY_GEN:
    case CKM_PBE_SHA1_DES3_EDE_CBC:
        *type = CKK_DES3;
        break;
    case CKM_AES_KEY_GEN:
        *type = CKK_AES;
        break;
    case CKM_AES_XTS_KEY_GEN:
        *type = CKK_AES_XTS;
        break;
    case CKM_GENERIC_SECRET_KEY_GEN:
    case CKM_SHA1_KEY_DERIVATION:
    case CKM_SHA224_KEY_DERIVATION:
    case CKM_SHA256_KEY_DERIVATION:
    case CKM_SHA384_KEY_DERIVATION:
    case CKM_SHA512_KEY_DERIVATION:
    case CKM_SHA3_224_KEY_DERIVATION:
    case CKM_SHA3_256_KEY_DERIVATION:
    case CKM_SHA3_384_KEY_DERIVATION:
    case CKM_SHA3_512_KEY_DERIVATION:
        *type = CKK_GENERIC_SECRET;
        break;
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        *type = CKK_RSA;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        *type = CKK_EC;
        break;
    case CKM_DSA_KEY_PAIR_GEN:
        *type = CKK_DSA;
        break;
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        *type = CKK_DH;
        break;
    case CKM_IBM_DILITHIUM:
        *type = CKK_IBM_PQC_DILITHIUM;
        break;
    case CKM_IBM_KYBER:
        *type = CKK_IBM_PQC_KYBER;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

void copy_token_contents_sensibly(CK_TOKEN_INFO_PTR pInfo,
                                  TOKEN_DATA *nv_token_data)
{
    memcpy(pInfo, &nv_token_data->token_info, sizeof(CK_TOKEN_INFO_32));
    pInfo->flags = nv_token_data->token_info.flags;
    pInfo->ulMaxPinLen = nv_token_data->token_info.ulMaxPinLen;
    pInfo->ulMinPinLen = nv_token_data->token_info.ulMinPinLen;

    if (nv_token_data->token_info.ulTotalPublicMemory ==
        (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION) {
        pInfo->ulTotalPublicMemory = (CK_ULONG) CK_UNAVAILABLE_INFORMATION;
    } else {
        pInfo->ulTotalPublicMemory =
            nv_token_data->token_info.ulTotalPublicMemory;
    }

    if (nv_token_data->token_info.ulFreePublicMemory ==
        (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION) {
        pInfo->ulFreePublicMemory = (CK_ULONG) CK_UNAVAILABLE_INFORMATION;
    } else {
        pInfo->ulFreePublicMemory =
            nv_token_data->token_info.ulFreePublicMemory;
    }

    if (nv_token_data->token_info.ulTotalPrivateMemory ==
        (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION) {
        pInfo->ulTotalPrivateMemory = (CK_ULONG) CK_UNAVAILABLE_INFORMATION;
    } else {
        pInfo->ulTotalPrivateMemory =
            nv_token_data->token_info.ulTotalPrivateMemory;
    }

    if (nv_token_data->token_info.ulFreePrivateMemory ==
        (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION) {
        pInfo->ulFreePrivateMemory = (CK_ULONG) CK_UNAVAILABLE_INFORMATION;
    } else {
        pInfo->ulFreePrivateMemory =
            nv_token_data->token_info.ulFreePrivateMemory;
    }

    pInfo->hardwareVersion = nv_token_data->token_info.hardwareVersion;
    pInfo->firmwareVersion = nv_token_data->token_info.firmwareVersion;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    /* pInfo->ulSessionCount is set at the API level */
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    /* pInfo->ulRwSessionCount is set at the API level */
}

CK_RV init_hsm_mk_change_lock(STDLL_TokData_t *tokdata)
{
    pthread_rwlockattr_t attr;

    /*
     * Request the API layer to lock against HSM-MK-change state changes.
     * Set lock kind PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP to avoid
     * writer starvation - but only on Linux. This is a non-portable GNU
     * extension, with no POSIX mechanism to achieve a similar functionality.
     * Otherwise in a multi-threaded OCK application
     * with a heavy crypto workload, the event thread would never get the
     * HSM-MK-change lock as writer.
     */
    if (pthread_rwlockattr_init(&attr) != 0) {
        TRACE_ERROR("pthread_rwlockattr_init failed\n");
        OCK_SYSLOG(LOG_ERR, "%s: Failed to initialize the HSM-MK-change lock\n",
                   __func__);
        return CKR_CANT_LOCK;
    }

#if !defined(_AIX)
#if _XOPEN_SOURCE >= 500 || _POSIX_C_SOURCE >= 200809L
    if (pthread_rwlockattr_setkind_np(&attr,
                  PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) != 0) {
        TRACE_ERROR("pthread_rwlockattr_setkind_np failed\n");
        OCK_SYSLOG(LOG_ERR, "%s: Failed to initialize the HSM-MK-change lock\n",
                   __func__);
        pthread_rwlockattr_destroy(&attr);
        return CKR_CANT_LOCK;
    }
#endif /* _XOPEN_SOURCE >= 500 || _POSIX_C_SOURCE >= 200809L */
#endif /* _AIX */

    if (pthread_rwlock_init(&tokdata->hsm_mk_change_rwlock, &attr) != 0) {
        TRACE_ERROR("pthread_rwlock_init failed\n");
        OCK_SYSLOG(LOG_ERR, "%s: Failed to initialize the HSM-MK-change lock\n",
                   __func__);
        pthread_rwlockattr_destroy(&attr);
        return CKR_CANT_LOCK;
    }

    pthread_rwlockattr_destroy(&attr);

    tokdata->hsm_mk_change_supported = TRUE;

    return CKR_OK;
}
