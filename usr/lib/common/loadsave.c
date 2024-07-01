/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// loadsave.c
//
// routines associated with loading/saving files
//
//
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/file.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/evp.h>

#include "platform.h"
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "sw_crypt.h"
#include "trace.h"
#include "ock_syslog.h"
#include "slotmgr.h" // for ock_snprintf

CK_RV set_perm(int, const char *group);

CK_RV restore_private_token_object_old(STDLL_TokData_t *tokdata, CK_BYTE *data,
                                       CK_ULONG len, OBJECT *pObj,
                                       const char *fname);
CK_RV reload_token_object_old(STDLL_TokData_t *tokdata, OBJECT *obj);
CK_RV save_public_token_object_old(STDLL_TokData_t *tokdata, OBJECT *obj);
CK_RV load_public_token_objects_old(STDLL_TokData_t *tokdata);

static int get_token_object_path(char *buf, size_t buflen,
                                 STDLL_TokData_t *tokdata, char *path)
{
    if (ock_snprintf(buf, buflen, "%s/" PK_LITE_OBJ_DIR "/%s",
                     tokdata->data_store, path) != 0) {
        TRACE_ERROR("buffer overflow for object path %s", path);
        return -1;
    }
    return 0;
}

static FILE *open_token_object_path(char *buf, size_t buflen,
                                    STDLL_TokData_t *tokdata, char *path,
                                    char *mode)
{
    if (get_token_object_path(buf, buflen, tokdata, path) < 0)
        return NULL;
    return fopen(buf, mode);
}

static int get_token_data_store_path(char *buf, size_t buflen,
                                     STDLL_TokData_t *tokdata, char *path)
{
    if (ock_snprintf(buf, buflen, "%s/%s", tokdata->data_store, path)) {
        TRACE_ERROR("buffer overflow for path %s", path);
        return -1;
    }
    return 0;
}

static FILE *open_token_data_store_path(char *buf, size_t buflen,
                                        STDLL_TokData_t *tokdata, char *path,
                                        char *mode)
{
    if (get_token_data_store_path(buf, buflen, tokdata, path) < 0)
        return NULL;
    return fopen(buf, mode);
}

static FILE *open_token_object_index(char *buf, size_t buflen,
                                     STDLL_TokData_t *tokdata, char *mode)
{
    return open_token_object_path(buf, buflen, tokdata, PK_LITE_OBJ_IDX, mode);
}

static FILE *open_token_nvdat(char *buf, size_t buflen,
                              STDLL_TokData_t *tokdata, char *mode)
{
    if (ock_snprintf(buf, buflen, "%s/" PK_LITE_NV, tokdata->data_store)) {
        TRACE_ERROR("NVDAT.TOK file name buffer overflow\n");
        return NULL;
    }
    return fopen(buf, mode);
}

char *get_pk_dir(STDLL_TokData_t *tokdata, char *fname, size_t len)
{
    int snres;
    struct passwd *pw = NULL;

    if (token_specific.data_store.per_user && (pw = getpwuid(geteuid())) != NULL)
        snres = ock_snprintf(fname, len, "%s/%s", tokdata->pk_dir, pw->pw_name);
    else
        snres = ock_snprintf(fname, len, "%s", tokdata->pk_dir);
    return snres != 0 ? NULL : fname;
}

CK_RV set_perm(int file, const char *group)
{
    struct stat sb;
    struct group *grp;
    mode_t mode;

    if (group == NULL || group[0] == '\0')
        group = PKCS_GROUP;

    if (fstat(file, &sb) != 0) {
        TRACE_DEVEL("fstat failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    grp = getgrnam(group);
    if (grp == NULL) {
        TRACE_DEVEL("getgrnam(%s) failed: %s\n", group, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.data_store.per_user) {
        /*
         * In the TPM token, with per user data stores, we don't share
         * the token object amongst a group. In fact, we want to
         * restrict access to a single user.
         * Only change the file mode if its not already as expected.
         */
        if (S_ISDIR(sb.st_mode))
            mode = S_IRUSR | S_IWUSR | S_IXUSR;
        else
            mode = S_IRUSR | S_IWUSR;

        if ((sb.st_mode & ~S_IFMT) != mode) {
            if (fchmod(file, mode) != 0) {
                TRACE_DEVEL("fchmod(rw-------) failed: %s\n", strerror(errno));
                return CKR_FUNCTION_FAILED;
            }
        }
    } else {
        /* Set absolute permissions or rw-rw----, if not already as expected */
        if (S_ISDIR(sb.st_mode))
            mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
        else
            mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

        if ((sb.st_mode & ~S_IFMT) != mode) {
            if (fchmod(file, mode) != 0) {
                TRACE_DEVEL("fchmod(rw-rw----) failed: %s\n", strerror(errno));
                return CKR_FUNCTION_FAILED;
            }
        }

        /* set ownership to pkcs11 group, if not already as expected */
        if (sb.st_gid != grp->gr_gid) {
            if (fchown(file, -1, grp->gr_gid) != 0) {
                TRACE_DEVEL("fchown(-1, %s) failed: %s\n", group,
                             strerror(errno));
                return CKR_FUNCTION_FAILED;
            }
        }
    }

    return CKR_OK;
}

//
// Note: The token lock (XProcLock) must be held when calling this function.
// The object must hold the READ lock when this function is called.
//
CK_RV save_token_object(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    FILE *fp = NULL;
    char line[256];
    char fname[PATH_MAX];
    CK_RV rc;

    // write token object
    if (object_is_private(obj) == TRUE)
        rc = save_private_token_object(tokdata, obj);
    else
        rc = save_public_token_object(tokdata, obj);
    if (rc != CKR_OK)
        return rc;

    // update the index file if it exists
    fp = open_token_object_index(fname, sizeof(fname), tokdata, "r");
    if (fp) {
        rc = set_perm(fileno(fp), tokdata->tokgroup);
        if (rc != CKR_OK) {
            fclose(fp);
            return rc;
        }
        while (fgets(line, 50, fp)) {
            line[strlen(line) - 1] = 0;
            if (strcmp(line, (char *)obj->name) == 0) {
                fclose(fp);
                // object is already in the list
                return CKR_OK;
            }
        }
        fclose(fp);
    }
    // we didn't find it...either the index file doesn't exist or this
    // is a new object...
    //
    fp = fopen(fname, "a");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK) {
        fclose(fp);
        return rc;
    }

    fprintf(fp, "%s\n", obj->name);
    fclose(fp);

    return CKR_OK;
}

//
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV delete_token_object(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    FILE *fp1, *fp2;
    char objidx[PATH_MAX], idxtmp[PATH_MAX], fname[PATH_MAX], line[256];
    CK_RV rc;

    // FIXME:  on UNIX, we need to make sure these guys aren't symlinks
    //         before we blindly write to these files...
    //

    // remove the object from the index file
    //

    fp1 = open_token_object_index(objidx, sizeof(objidx), tokdata, "r");
    fp2 = open_token_object_path(idxtmp, sizeof(idxtmp),
                                 tokdata, "IDX.TMP", "w");
    if (!fp1 || !fp2) {
        if (fp1)
            fclose(fp1);
        if (fp2)
            fclose(fp2);
        TRACE_ERROR("fopen failed\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = set_perm(fileno(fp2), tokdata->tokgroup);
    if (rc != CKR_OK) {
        fclose(fp1);
        fclose(fp2);
        return rc;
    }

    while (fgets(line, 50, fp1)) {
        line[strlen(line) - 1] = 0;
        if (strcmp(line, (char *)obj->name) == 0)
            continue;
        else
            fprintf(fp2, "%s\n", line);
    }

    fclose(fp1);
    fclose(fp2);
    fp2 = fopen(objidx, "w");
    fp1 = fopen(idxtmp, "r");
    if (!fp1 || !fp2) {
        if (fp1)
            fclose(fp1);
        if (fp2)
            fclose(fp2);
        TRACE_ERROR("fopen failed\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = set_perm(fileno(fp2), tokdata->tokgroup);
    if (rc != CKR_OK) {
        fclose(fp1);
        fclose(fp2);
        return rc;
    }

    while (fgets(line, 50, fp1)) {
        fprintf(fp2, "%s", line);
    }

    fclose(fp1);
    fclose(fp2);

    if (get_token_object_path(fname, sizeof(fname), tokdata,
                              (char *) obj->name) < 0)
       TRACE_DEVEL("file name buffer overflow in obj unlink\n");
    else
        unlink(fname);

    return CKR_OK;
}

CK_RV delete_token_data(STDLL_TokData_t *tokdata)
{
    CK_RV rc = CKR_OK;
    char *cmd = NULL;

    // Construct a string to delete the token objects.
    //
    // META This should be fine since the open session checking
    // should occur at the API not the STDLL
    //
    // TODO: Implement delete_all_files_in_dir() */
    if (asprintf(&cmd, "%s %s/%s/* > /dev/null 2>&1", DEL_CMD,
                 tokdata->data_store, PK_LITE_OBJ_DIR) < 0) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (system(cmd))
        TRACE_ERROR("system() failed.\n");

done:
    free(cmd);

    return rc;
}

CK_RV init_data_store(STDLL_TokData_t *tokdata, char *directory,
                      char *data_store, size_t len)
{
    char *pkdir;
    int pklen;
    struct stat statbuf;
    struct group *grp;
    const char *group;

    if (tokdata->pk_dir != NULL) {
        free(tokdata->pk_dir);
        tokdata->pk_dir = NULL;
    }

    if ((pkdir = secure_getenv("PKCS_APP_STORE")) != NULL) {
        pklen = strlen(pkdir) + 1024;
        tokdata->pk_dir = (char *) calloc(pklen, 1);
        if (!(tokdata->pk_dir))
            return CKR_HOST_MEMORY;
        if (ock_snprintf(tokdata->pk_dir, pklen, "%s/%s", pkdir, SUB_DIR) != 0)
            return CKR_FUNCTION_FAILED;
        if (get_pk_dir(tokdata, data_store, len) == NULL)
            return CKR_FUNCTION_FAILED;
        goto check;
    }

    if (directory) {
        pklen = strlen(directory) + 1;
        tokdata->pk_dir = (char *) calloc(pklen, 1);
        if (!(tokdata->pk_dir))
            return CKR_HOST_MEMORY;
        if (ock_snprintf(tokdata->pk_dir, pklen, "%s", directory) != 0)
            return CKR_FUNCTION_FAILED;
    } else {
        pklen = strlen(PK_DIR) + 1;
        tokdata->pk_dir = (char *) calloc(pklen, 1);
        if (!(tokdata->pk_dir))
            return CKR_HOST_MEMORY;
        if (ock_snprintf(tokdata->pk_dir, pklen, "%s", PK_DIR) != 0)
            return CKR_FUNCTION_FAILED;
    }
    if (get_pk_dir(tokdata, data_store, len) == NULL)
        return CKR_FUNCTION_FAILED;

check:
    group = tokdata->tokgroup;
    if (group == NULL || group[0] == '\0')
        group = PKCS_GROUP;

    grp = getgrnam(group);
    if (grp == NULL) {
        OCK_SYSLOG(LOG_ERR, "getgrname(%s): %s\n", group, strerror(errno));
        TRACE_ERROR("getgrname(%s): %s\n", group, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    if (stat(tokdata->pk_dir, &statbuf) != 0) {
        OCK_SYSLOG(LOG_ERR, "Could not stat directory '%s': %s\n",
                   tokdata->pk_dir, strerror(errno));
        TRACE_ERROR("Could not stat directory '%s': %s\n", tokdata->pk_dir,
                    strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    if (statbuf.st_gid != grp->gr_gid) {
        OCK_SYSLOG(LOG_ERR, "Directory '%s' is not owned by token group '%s'\n",
                tokdata->pk_dir, group);
        TRACE_ERROR("Directory '%s' is not owned by token group '%s'\n",
                tokdata->pk_dir, group);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

void final_data_store(STDLL_TokData_t * tokdata)
{
    if (tokdata->pk_dir != NULL) {
        free(tokdata->pk_dir);
        tokdata->pk_dir = NULL;
    }
}

/******************************************************************************
 * tokversion < 3.12 object store
 */

static CK_RV get_encryption_info(CK_ULONG *p_key_len, CK_ULONG *p_block_size)
{
    CK_ULONG key_len = 0L;
    CK_ULONG block_size = 0L;

    switch (token_specific.data_store.encryption_algorithm) {
    case CKM_DES3_CBC:
        key_len = 3 * DES_KEY_SIZE;
        block_size = DES_BLOCK_SIZE;
        break;
    case CKM_AES_CBC:
        key_len = AES_KEY_SIZE_256;
        block_size = AES_BLOCK_SIZE;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    if (p_key_len)
        *p_key_len = key_len;
    if (p_block_size)
        *p_block_size = block_size;

    return CKR_OK;
}

static CK_BYTE *duplicate_initial_vector(const CK_BYTE *iv)
{
    CK_ULONG block_size = 0L;
    CK_BYTE *initial_vector = NULL;

    if (iv == NULL)
        goto done;

    if (get_encryption_info(NULL, &block_size) != CKR_OK)
        goto done;

    initial_vector = malloc(block_size);
    if (initial_vector == NULL) {
        goto done;
    }
    memcpy(initial_vector, iv, block_size);

done:
    return initial_vector;
}

static CK_RV encrypt_data_with_clear_key(STDLL_TokData_t *tokdata,
                                         CK_BYTE *key, CK_ULONG keylen,
                                         const CK_BYTE *iv,
                                         CK_BYTE *clear, CK_ULONG clear_len,
                                         CK_BYTE *cipher,
                                         CK_ULONG *p_cipher_len,
                                         CK_BBOOL mk_crypt)
{
#ifndef CLEARTEXT
    CK_RV rc = CKR_OK;
    CK_BYTE *initial_vector = NULL;

    initial_vector = duplicate_initial_vector(iv);
    if (initial_vector == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    switch (token_specific.data_store.encryption_algorithm) {
    case CKM_DES3_CBC:
        rc = sw_des3_cbc_encrypt(clear, clear_len,
                                 cipher, p_cipher_len, initial_vector, key);
        break;
    case CKM_AES_CBC:
        rc = sw_aes_cbc_encrypt(clear, clear_len, cipher, p_cipher_len,
                                initial_vector, key, keylen);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

    if (initial_vector)
        free(initial_vector);

    if (rc == CKR_OK &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0) {
        if (mk_crypt)
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.mk_crypt,
                                                tokdata->store_strength.mk_strength);
        else
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.wrap_crypt,
                                                tokdata->store_strength.wrap_strength);
    }

    return rc;

#else
    memcpy(cipher, clear, clear_len);
    return CKR_OK;
#endif
}

static CK_RV decrypt_data_with_clear_key(STDLL_TokData_t *tokdata,
                                         CK_BYTE *key, CK_ULONG keylen,
                                         const CK_BYTE *iv,
                                         CK_BYTE *cipher, CK_ULONG cipher_len,
                                         CK_BYTE *clear,
                                         CK_ULONG *p_clear_len,
                                         CK_BBOOL mk_crypt)
{
#ifndef CLEARTEXT
    CK_RV rc = CKR_OK;
    CK_BYTE *initial_vector = NULL;

    initial_vector = duplicate_initial_vector(iv);
    if (initial_vector == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    switch (token_specific.data_store.encryption_algorithm) {
    case CKM_DES3_CBC:
        rc = sw_des3_cbc_decrypt(cipher, cipher_len, clear, p_clear_len,
                                 initial_vector, key);
        break;
    case CKM_AES_CBC:
        rc = sw_aes_cbc_decrypt(cipher, cipher_len, clear, p_clear_len,
                                 initial_vector, key, keylen);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

    if (initial_vector)
        free(initial_vector);

    if (rc == CKR_OK &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0) {
        if (mk_crypt)
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.mk_crypt,
                                                tokdata->store_strength.mk_strength);
        else
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.wrap_crypt,
                                                tokdata->store_strength.wrap_strength);
    }

    return rc;

#else
    memcpy(clear, cipher, cipher_len);
    return CKR_OK;
#endif
}

//
//
CK_RV load_token_data_old(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
    FILE *fp = NULL;
    char fname[PATH_MAX];
    TOKEN_DATA td;
    CK_RV rc;

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        goto out_nolock;
    }

    fp = open_token_nvdat(fname, sizeof(fname), tokdata, "r");
    if (!fp) {
        /* Better error checking added */
        if (errno == ENOENT) {
            init_token_data(tokdata, slot_id);

            fp = fopen(fname, "r");
            if (!fp) {
                // were really hosed here since the created
                // did not occur
                TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
                rc = CKR_FUNCTION_FAILED;
                goto out_unlock;
            }
        } else {
            /* Could not open file for some unknown reason */
            TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            goto out_unlock;
        }
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto out_unlock;

    /* Load generic token data */
    if (fread(&td, sizeof(TOKEN_DATA_OLD), 1, fp) != 1) {
        TRACE_ERROR("fread(%s): %s\n", fname,
                    ferror(fp) ? strerror(errno) : "failed");
        rc = CKR_FUNCTION_FAILED;
        goto out_unlock;
    }
    memcpy(tokdata->nv_token_data, &td, sizeof(TOKEN_DATA_OLD));

    /* Load token-specific data */
    if (token_specific.t_load_token_data) {
        rc = token_specific.t_load_token_data(tokdata, slot_id, fp);
        if (rc)
            goto out_unlock;
    }

    rc = CKR_OK;

out_unlock:
    if (fp)
        fclose(fp);

    if (rc == CKR_OK) {
        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK)
            TRACE_ERROR("Failed to release Process Lock.\n");
    } else {
        /* return error that occurred first */
        XProcUnLock(tokdata);
    }

out_nolock:
    return rc;
}

//
//
CK_RV save_token_data_old(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
    FILE *fp = NULL;
    TOKEN_DATA td;
    CK_RV rc;
    char fname[PATH_MAX];

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        goto out_nolock;
    }

    fp = open_token_nvdat(fname, sizeof(fname), tokdata, "w");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    /* Write generic token data */
    memcpy(&td, tokdata->nv_token_data, sizeof(TOKEN_DATA_OLD));
    if (!fwrite(&td, sizeof(TOKEN_DATA_OLD), 1, fp)) {
        TRACE_ERROR("fwrite(%s): %s\n", fname,
                    ferror(fp) ? strerror(errno) : "failed");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Write token-specific data */
    if (token_specific.t_save_token_data) {
        rc = token_specific.t_save_token_data(tokdata, slot_id, fp);
        if (rc)
            goto done;
    }

    rc = CKR_OK;

done:
    if (fp)
        fclose(fp);

    if (rc == CKR_OK) {
        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK)
            TRACE_ERROR("Failed to release Process Lock.\n");
    } else {
        /* return error that occurred first */
        XProcUnLock(tokdata);
    }

out_nolock:
    return rc;
}


//
// Note: The token lock (XProcLock) must be held when calling this function.
//
static CK_RV save_private_token_object_old(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    FILE *fp = NULL;
    CK_BYTE *obj_data = NULL;
    CK_BYTE *clear = NULL;
    CK_BYTE *cipher = NULL;
    CK_BYTE *ptr = NULL;
    char fname[PATH_MAX];
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0L;
    CK_ULONG block_size = 0L;
    CK_ULONG obj_data_len, clear_len, cipher_len;
    CK_ULONG padded_len;
    CK_BBOOL flag;
    CK_RV rc;
    CK_ULONG_32 obj_data_len_32;
    CK_ULONG_32 total_len;

    rc = object_flatten(obj, &obj_data, &obj_data_len);
    obj_data_len_32 = obj_data_len;
    if (rc != CKR_OK) {
        goto error;
    }
    //
    // format for the object file:
    //    private flag
    //    ---- begin encrypted part        <--+
    //       length of object data            |
    //       object data                      +---- sensitive part
    //       SHA of (object data)             |
    //    ---- end encrypted part          <--+
    //
    rc = compute_sha1(tokdata, obj_data, obj_data_len, hash_sha);
    if (rc != CKR_OK)
        goto error;

    // encrypt the sensitive object data.  need to be careful.
    // if I use the normal high-level encryption routines I'll need to
    // create a tepmorary key object containing the master key, perform the
    // encryption, then destroy the key object.  There is a race condition
    // here if the application is multithreaded (if a thread-switch occurs,
    // the other application thread could do a FindObject and be able to
    // access the master key object.
    //
    // So I have to use the low-level encryption routines.
    //

    if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
        goto error;

    // Duplicate key
    key = malloc(key_len);
    if (!key)
        goto oom_error;
    memcpy(key, tokdata->master_key, key_len);


    clear_len = sizeof(CK_ULONG_32) + obj_data_len_32 + SHA1_HASH_SIZE;
    cipher_len = padded_len = block_size * (clear_len / block_size + 1);

    clear = malloc(padded_len);
    cipher = malloc(padded_len);
    if (!clear || !cipher)
        goto oom_error;

    // Build data that will be encrypted
    ptr = clear;
    memcpy(ptr, &obj_data_len_32, sizeof(CK_ULONG_32));
    ptr += sizeof(CK_ULONG_32);
    memcpy(ptr, obj_data, obj_data_len_32);
    ptr += obj_data_len_32;
    memcpy(ptr, hash_sha, SHA1_HASH_SIZE);

    add_pkcs_padding(clear + clear_len, block_size, clear_len, padded_len);

    rc = encrypt_data_with_clear_key(tokdata, key, key_len,
                                     token_specific.data_store.
                                     obj_initial_vector, clear, padded_len,
                                     cipher, &cipher_len, CK_FALSE);
    if (rc != CKR_OK) {
        goto error;
    }

    if (ock_snprintf(fname, PATH_MAX, "%s/%s/%.8s", tokdata->data_store,
                     PK_LITE_OBJ_DIR, (char *)obj->name) != 0) {
        TRACE_ERROR("private token object old name buffer overflow\n");
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }
    fp = fopen(fname, "w");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto error;

    total_len = sizeof(CK_ULONG_32) + sizeof(CK_BBOOL) + cipher_len;

    flag = TRUE;

    (void) fwrite(&total_len, sizeof(CK_ULONG_32), 1, fp);
    (void) fwrite(&flag, sizeof(CK_BBOOL), 1, fp);
    (void) fwrite(cipher, cipher_len, 1, fp);

    fclose(fp);
    free(obj_data);
    free(clear);
    free(cipher);
    free(key);

    return CKR_OK;

oom_error:
    rc = CKR_HOST_MEMORY;

error:
    if (obj_data)
        free(obj_data);
    if (clear)
        free(clear);
    if (cipher)
        free(cipher);
    if (key)
        free(key);
    if (fp != NULL)
        fclose(fp);

    return rc;
}

//
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV load_private_token_objects_old(STDLL_TokData_t *tokdata)
{
    FILE *fp1 = NULL, *fp2 = NULL;
    CK_BYTE *buf = NULL;
    char tmp[PATH_MAX];
    char iname[PATH_MAX];
    char fname[PATH_MAX];
    CK_BBOOL priv;
    CK_ULONG_32 size;
    CK_RV rc;
    size_t read_size;

    fp1 = open_token_object_index(iname, sizeof(iname), tokdata, "r");
    if (!fp1)
        return CKR_OK;          // no token objects

    while (fgets(tmp, 50, fp1)) {
        tmp[strlen(tmp) - 1] = 0;

        fp2 = open_token_object_path(fname, sizeof(fname), tokdata, tmp, "r");
        if (!fp2)
            continue;

        if (fread(&size, sizeof(CK_ULONG_32), 1, fp2) != 1) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Cannot read size\n");
            continue;
        }
        if (fread(&priv, sizeof(CK_BBOOL), 1, fp2) != 1) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Cannot read boolean\n");
            continue;
        }
        if (priv == FALSE) {
            fclose(fp2);
            continue;
        }
        if (size <= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL)) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Improper size of object %s (ignoring it)\n",
                       fname);
            continue;
        }

        size -= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);
        buf = (CK_BYTE *) malloc(size);
        if (!buf) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot malloc %u bytes to read in "
                       "token object %s (ignoring it)", size, fname);
            continue;
        }

        read_size = fread(buf, 1, size, fp2);
        if (read_size != size) {
            free(buf);
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot read token object %s " "(ignoring it)", fname);
            continue;
        }

        rc = restore_private_token_object_old(tokdata, buf, size, NULL, fname);
        if (rc != CKR_OK)
            goto error;

        free(buf);
        fclose(fp2);
    }

    fclose(fp1);

    return CKR_OK;

error:
    if (buf)
        free(buf);
    if (fp1)
        fclose(fp1);
    if (fp2)
        fclose(fp2);

    return rc;
}

//
//
CK_RV load_masterkey_so_old(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_BYTE *cipher = NULL;
    CK_BYTE *clear = NULL;
    CK_BYTE *key = NULL;
    CK_ULONG data_len;
    CK_ULONG cipher_len, clear_len;
    CK_RV rc;
    char fname[PATH_MAX];
    CK_ULONG key_len = 0L;
    CK_ULONG master_key_len = 0L;
    CK_ULONG block_size = 0L;
    struct stat sb;

    if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
        goto done;

    master_key_len = key_len;
    memset(tokdata->master_key, 0x0, master_key_len);

    data_len = master_key_len + SHA1_HASH_SIZE;
    clear_len = cipher_len = (data_len + block_size - 1)
        & ~(block_size - 1);

    sprintf(fname, "%s/MK_SO", tokdata->data_store);
    if (stat(fname, &sb) != 0) {
        TRACE_ERROR("stat(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if ((CK_ULONG)sb.st_size > cipher_len &&
        token_specific.secure_key_token &&
        strcmp(token_specific.token_subdir, "ccatok") == 0) {
        /*
         * The CCA token used to have a secure master key length of 64, although
         * it uses clear keys for the master key in the meantime. The master key
         * length  has an influence on the file size of the MK_SO and MK_USER
         * files when using the old pin encryption format. Use special handling
         * for such larger MK_SO files, and accept the larger length. Newly
         * written MK_SO files will use the clear key master key length, but we
         * need to be able to read larger files for backwards compatibility.
         */
        master_key_len = 64;

        data_len = master_key_len + SHA1_HASH_SIZE;
        clear_len = cipher_len = (data_len + block_size - 1)
             & ~(block_size - 1);
    }

    key = malloc(key_len);
    cipher = malloc(cipher_len);
    clear = malloc(clear_len);
    if (key == NULL || cipher == NULL || clear == NULL) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    // this file gets created on C_InitToken so we can assume that it always
    // exists
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_SO", "r");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fread(cipher, cipher_len, 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fread() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    // decrypt the master key data using the MD5 of the SO key
    // (we can't use the SHA of the SO key since the SHA of the key is
    // stored in the token data file).
    memcpy(key, tokdata->so_pin_md5, MD5_HASH_SIZE);
    memcpy(key + MD5_HASH_SIZE, tokdata->so_pin_md5, key_len - MD5_HASH_SIZE);

    rc = decrypt_data_with_clear_key(tokdata, key, key_len,
                                     token_specific.data_store.
                                     pin_initial_vector, cipher, cipher_len,
                                     clear, &clear_len, CK_TRUE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("decrypt_data_with_clear_key failed.\n");
        goto done;
    }
    //
    // technically should strip PKCS padding here but since I already know
    // what the length should be, I don't bother.
    //

    // compare the hashes
    //
    rc = compute_sha1(tokdata, clear, master_key_len, hash_sha);
    if (rc != CKR_OK) {
        goto done;
    }

    if (memcmp(hash_sha, clear + master_key_len, SHA1_HASH_SIZE) != 0) {
        TRACE_ERROR("masterkey hashes do not match\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    memcpy(tokdata->master_key, clear, master_key_len);
    rc = CKR_OK;

done:
    if (fp)
        fclose(fp);
    if (clear)
        free(clear);
    if (cipher)
        free(cipher);
    if (key)
        free(key);

    return rc;
}

//
//
CK_RV load_masterkey_user_old(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_BYTE *cipher = NULL;
    CK_BYTE *clear = NULL;
    CK_BYTE *key = NULL;
    CK_ULONG data_len;
    CK_ULONG cipher_len, clear_len;
    CK_RV rc;
    char fname[PATH_MAX];
    CK_ULONG key_len = 0L;
    CK_ULONG master_key_len = 0L;
    CK_ULONG block_size = 0L;
    struct stat sb;

    if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
        goto done;

    master_key_len = key_len;
    memset(tokdata->master_key, 0x0, master_key_len);

    data_len = master_key_len + SHA1_HASH_SIZE;
    clear_len = cipher_len = (data_len + block_size - 1)
        & ~(block_size - 1);

    sprintf(fname, "%s/MK_USER", tokdata->data_store);
    if (stat(fname, &sb) != 0) {
        TRACE_ERROR("stat(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if ((CK_ULONG)sb.st_size > cipher_len &&
        token_specific.secure_key_token &&
        strcmp(token_specific.token_subdir, "ccatok") == 0) {
        /*
         * The CCA token used to have a secure master key length of 64, although
         * it uses clear keys for the master key in the meantime. The master key
         * length  has an influence on the file size of the MK_SO and MK_USER
         * files when using the old pin encryption format. Use special handling
         * for such larger MK_USER files, and accept the larger length. Newly
         * written MK_USER files will use the clear key master key length, but
         * we need to be able to read larger files for backwards compatibility.
         */
        master_key_len = 64;

        data_len = master_key_len + SHA1_HASH_SIZE;
        clear_len = cipher_len = (data_len + block_size - 1)
             & ~(block_size - 1);
    }

    key = malloc(key_len);
    cipher = malloc(cipher_len);
    clear = malloc(clear_len);
    if (key == NULL || cipher == NULL || clear == NULL) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    // this file gets created on C_InitToken so we can assume that it always
    // exists
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_USER", "r");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fread(cipher, cipher_len, 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fread failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    // decrypt the master key data using the MD5 of the SO key
    // (we can't use the SHA of the SO key since the SHA of the key is
    // stored in the token data file).
    memcpy(key, tokdata->user_pin_md5, MD5_HASH_SIZE);
    memcpy(key + MD5_HASH_SIZE, tokdata->user_pin_md5, key_len - MD5_HASH_SIZE);

    rc = decrypt_data_with_clear_key(tokdata, key, key_len,
                                     token_specific.data_store.
                                     pin_initial_vector, cipher, cipher_len,
                                     clear, &clear_len, CK_TRUE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("decrypt_data_with_clear_key failed.\n");
        goto done;
    }
    //
    // technically should strip PKCS padding here but since I already know
    // what the length should be, I don't bother.
    //

    // compare the hashes
    //
    rc = compute_sha1(tokdata, clear, master_key_len, hash_sha);
    if (rc != CKR_OK) {
        goto done;
    }

    if (memcmp(hash_sha, clear + master_key_len, SHA1_HASH_SIZE) != 0) {
        TRACE_ERROR("User's masterkey hashes do not match.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    memcpy(tokdata->master_key, clear, master_key_len);
    rc = CKR_OK;

done:
    if (fp)
        fclose(fp);
    if (key)
        free(key);
    if (clear)
        free(clear);
    if (cipher)
        free(cipher);

    return rc;
}

//
//
CK_RV save_masterkey_so_old(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    CK_BYTE *clear = NULL;
    CK_ULONG clear_len = 0L;
    CK_BYTE *cipher = NULL;
    CK_ULONG cipher_len = 0L;
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0L;
    CK_ULONG block_size = 0L;
    CK_ULONG data_len = 0L;
    char fname[PATH_MAX];
    CK_RV rc;

    /* Skip it if master key is not needed. */
    if (!token_specific.data_store.use_master_key)
        return CKR_OK;

    if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
        goto done;

    data_len = key_len + SHA1_HASH_SIZE;
    cipher_len = clear_len = block_size * (data_len / block_size + 1);

    key = malloc(key_len);
    clear = malloc(clear_len);
    cipher = malloc(cipher_len);
    if (key == NULL || clear == NULL || cipher == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    // Copy data to buffer (key+hash)
    memcpy(clear, tokdata->master_key, key_len);
    if ((rc = compute_sha1(tokdata, tokdata->master_key,
                           key_len, clear + key_len)) != CKR_OK)
        goto done;
    add_pkcs_padding(clear + data_len, block_size, data_len, clear_len);

    // encrypt the key data
    memcpy(key, tokdata->so_pin_md5, MD5_HASH_SIZE);
    memcpy(key + MD5_HASH_SIZE, tokdata->so_pin_md5, key_len - MD5_HASH_SIZE);

    rc = encrypt_data_with_clear_key(tokdata, key, key_len,
                                     token_specific.data_store.
                                     pin_initial_vector, clear, clear_len,
                                     cipher, &cipher_len, CK_TRUE);
    if (rc != CKR_OK) {
        goto done;
    }
    // write the file
    //
    // probably ought to ensure the permissions are correct
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_SO", "w");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fwrite(cipher, cipher_len, 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fwrite failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;

done:
    if (fp)
        fclose(fp);
    if (key)
        free(key);
    if (clear)
        free(clear);
    if (cipher)
        free(cipher);

    return rc;
}

//
//
CK_RV save_masterkey_user_old(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    CK_BYTE *clear = NULL;
    CK_ULONG clear_len = 0L;
    CK_BYTE *cipher = NULL;
    CK_ULONG cipher_len = 0L;
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0L;
    CK_ULONG block_size = 0L;
    CK_ULONG data_len = 0L;
    char fname[PATH_MAX];
    CK_RV rc;

    if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
        goto done;

    data_len = key_len + SHA1_HASH_SIZE;
    cipher_len = clear_len = block_size * (data_len / block_size + 1);

    key = malloc(key_len);
    clear = malloc(clear_len);
    cipher = malloc(cipher_len);
    if (key == NULL || clear == NULL || cipher == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    // Copy data to buffer (key+hash)
    memcpy(clear, tokdata->master_key, key_len);
    if ((rc = compute_sha1(tokdata, tokdata->master_key,
                           key_len, clear + key_len)) != CKR_OK)
        goto done;
    add_pkcs_padding(clear + data_len, block_size, data_len, clear_len);

    // encrypt the key data
    memcpy(key, tokdata->user_pin_md5, MD5_HASH_SIZE);
    memcpy(key + MD5_HASH_SIZE, tokdata->user_pin_md5, key_len - MD5_HASH_SIZE);

    rc = encrypt_data_with_clear_key(tokdata, key, key_len,
                                     token_specific.data_store.
                                     pin_initial_vector, clear, clear_len,
                                     cipher, &cipher_len, CK_TRUE);
    if (rc != CKR_OK) {
        goto done;
    }
    // write the file
    //
    // probably ought to ensure the permissions are correct
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_USER", "w");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fwrite(cipher, cipher_len, 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fwrite failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;

done:
    if (fp)
        fclose(fp);
    if (key)
        free(key);
    if (clear)
        free(clear);
    if (cipher)
        free(cipher);

    return rc;
}

CK_RV generate_master_key_old(STDLL_TokData_t *tokdata, CK_BYTE *key)
{
    CK_RV rc = CKR_OK;
    CK_ULONG key_len = 0L;
    CK_ULONG master_key_len;
    CK_BYTE *master_key = NULL;
    CK_BBOOL is_opaque = FALSE;
    TEMPLATE *tmpl = NULL;

    /* Skip it if master key is not needed. */
    if (!token_specific.data_store.use_master_key)
        return CKR_OK;

    if (get_encryption_info(&key_len, NULL) != CKR_OK)
        return CKR_FUNCTION_FAILED;

    /* For secure key tokens, object encrypt/decrypt uses
     * software(openssl), not token. So generate masterkey via RNG.
     */
    if (token_specific.secure_key_token) {
        rc = rng_generate(tokdata, key, key_len);

        if (rc == CKR_OK &&
            (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.mk_keygen,
                                                tokdata->store_strength.mk_strength);

        return rc;
    }

    /* For clear key tokens, let token generate masterkey
     * since token will also encrypt/decrypt the objects.
     */
    tmpl = (TEMPLATE *)calloc(1, sizeof(TEMPLATE));
    if (tmpl == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    switch (token_specific.data_store.encryption_algorithm) {
    case CKM_DES3_CBC:
        rc = token_specific.t_des_key_gen(tokdata, tmpl, &master_key,
                                          &master_key_len, key_len,
                                          &is_opaque);
        break;
    case CKM_AES_CBC:
        rc = token_specific.t_aes_key_gen(tokdata, tmpl, &master_key,
                                          &master_key_len, key_len,
                                          &is_opaque);
        break;
    default:
        template_free(tmpl);
        return CKR_MECHANISM_INVALID;
    }

    template_free(tmpl);

    if (rc != CKR_OK)
        return rc;

    if (master_key_len != key_len) {
        TRACE_ERROR("Invalid master key size: %lu\n", master_key_len);
        free(master_key);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(key, master_key, master_key_len);
    free(master_key);

    if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id,
                                            &tokdata->store_strength.mk_keygen,
                                            tokdata->store_strength.mk_strength);

    return CKR_OK;
}

CK_RV restore_private_token_object_old(STDLL_TokData_t *tokdata, CK_BYTE *data,
                                       CK_ULONG len, OBJECT *pObj,
                                       const char *fname)
{
    CK_BYTE *clear = NULL;
    CK_BYTE *obj_data = NULL;
    CK_BYTE *ptr = NULL;
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0;
    CK_ULONG block_size;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_ULONG clear_len, obj_data_len;
    CK_RV rc;

    // format for the object data:
    //    (private flag has already been read at this point)
    //    ---- begin encrypted part
    //       length of object data
    //       object data
    //       SHA of object data
    //    ---- end encrypted part
    //

    clear_len = len;

    clear = (CK_BYTE *) malloc(len);
    if (!clear) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
        goto done;

    // decrypt the encrypted chunk
    key = malloc(key_len);
    if (!key) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    memcpy(key, tokdata->master_key, key_len);

    rc = decrypt_data_with_clear_key(tokdata, key, key_len,
                                     token_specific.data_store.
                                     obj_initial_vector, data, len, clear,
                                     &clear_len, CK_FALSE);
    if (rc != CKR_OK) {
        goto done;
    }

    rc = strip_pkcs_padding(clear, len, &clear_len);

    // if the padding extraction didn't work it means the object was
    // tampered with or the key was incorrect
    //
    if (rc != CKR_OK || (clear_len > len)) {
        TRACE_DEVEL("strip_pkcs_padding failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    ptr = clear;

    obj_data_len = *(CK_ULONG_32 *) ptr;

    // prevent buffer overflow in sha_update
    if (obj_data_len > clear_len) {
        TRACE_ERROR("stripped length is greater than clear length\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    ptr += sizeof(CK_ULONG_32);
    obj_data = ptr;

    // check the hash
    //
    rc = compute_sha1(tokdata, ptr, obj_data_len, hash_sha);
    if (rc != CKR_OK) {
        goto done;
    }
    ptr += obj_data_len;

    if (memcmp(ptr, hash_sha, SHA1_HASH_SIZE) != 0) {
        TRACE_ERROR("stored hash does not match restored data hash.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    // okay.  at this point, we're satisfied that nobody has tampered with
    // the token object...
    //

    rc = object_mgr_restore_obj(tokdata, obj_data, pObj, fname);
    if (rc != CKR_OK) {
        goto done;
    }
    rc = CKR_OK;

done:
    if (clear)
        free(clear);
    if (key)
        free(key);

    return rc;
}

//
//
CK_RV reload_token_object_old(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    FILE *fp = NULL;
    CK_BYTE *buf = NULL;
    char fname[PATH_MAX];
    CK_BBOOL priv;
    CK_ULONG_32 size;
    CK_ULONG size_64;
    CK_RV rc;
    size_t read_size;

    if (ock_snprintf(fname, PATH_MAX, "%s/%s/%.8s", tokdata->data_store,
                     PK_LITE_OBJ_DIR, (char *)obj->name) != 0) {
        TRACE_ERROR("token object file name buffer overflow\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    fp = fopen(fname, "r");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    if (fread(&size, sizeof(CK_ULONG_32), 1, fp) != 1) {
        OCK_SYSLOG(LOG_ERR, "Cannot read size\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (fread(&priv, sizeof(CK_BBOOL), 1, fp) != 1) {
        OCK_SYSLOG(LOG_ERR, "Cannot read boolean\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (size <= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL)) {
        rc = CKR_FUNCTION_FAILED;
        OCK_SYSLOG(LOG_ERR, "Improper size of object %s (ignoring it)\n",
                   fname);
        goto done;
    }

    size -= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);

    buf = (CK_BYTE *) malloc(size);
    if (!buf) {
        rc = CKR_HOST_MEMORY;
        OCK_SYSLOG(LOG_ERR,
                   "Cannot malloc %u bytes to read in token object %s "
                   "(ignoring it)", size, fname);
        goto done;
    }

    read_size = fread(buf, 1, size, fp);
    if (read_size != size) {
        OCK_SYSLOG(LOG_ERR,
                   "Token object %s appears corrupted (ignoring it)", fname);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    size_64 = size;

    if (priv)
        rc = restore_private_token_object_old(tokdata, buf, size_64, obj,
                                              fname);
    else
        rc = object_mgr_restore_obj(tokdata, buf, obj, fname);

done:
    if (fp)
        fclose(fp);
    if (buf)
        free(buf);

    return rc;
}

// this is the same as the old version.  public token objects are stored in the
// clear
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV save_public_token_object_old(STDLL_TokData_t *tokdata, OBJECT * obj)
{
    FILE *fp = NULL;
    CK_BYTE *clear = NULL;
    char fname[PATH_MAX];
    CK_ULONG clear_len;
    CK_BBOOL flag = FALSE;
    CK_RV rc;
    CK_ULONG_32 total_len;

    rc = object_flatten(obj, &clear, &clear_len);
    if (rc != CKR_OK) {
        goto error;
    }

    if (ock_snprintf(fname, PATH_MAX, "%s/%s/%.8s", tokdata->data_store,
                     PK_LITE_OBJ_DIR, (char *)obj->name) != 0) {
        TRACE_ERROR("public token object file name buffer overflow\n");
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }
    fp = fopen(fname, "w");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto error;

    total_len = clear_len + sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);

    (void) fwrite(&total_len, sizeof(CK_ULONG_32), 1, fp);
    (void) fwrite(&flag, sizeof(CK_BBOOL), 1, fp);
    (void) fwrite(clear, clear_len, 1, fp);

    fclose(fp);
    free(clear);

    return CKR_OK;

error:
    if (clear)
        free(clear);
    if (fp != NULL)
        fclose(fp);

    return rc;
}

//
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV load_public_token_objects_old(STDLL_TokData_t *tokdata)
{
    FILE *fp1 = NULL, *fp2 = NULL;
    CK_BYTE *buf = NULL;
    char tmp[PATH_MAX];
    char iname[PATH_MAX];
    char fname[PATH_MAX];
    CK_BBOOL priv;
    CK_ULONG_32 size;
    size_t read_size;

    fp1 = open_token_object_index(iname, sizeof(iname), tokdata, "r");
    if (!fp1)
        return CKR_OK;          // no token objects

    while (fgets(tmp, 50, fp1)) {
        tmp[strlen(tmp) - 1] = 0;

        fp2 = open_token_object_path(fname, sizeof(fname), tokdata, tmp, "r");
        if (!fp2)
            continue;

        if (fread(&size, sizeof(CK_ULONG_32), 1, fp2) != 1) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Cannot read size\n");
            continue;
        }
        if (fread(&priv, sizeof(CK_BBOOL), 1, fp2) != 1) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Cannot read boolean\n");
            continue;
        }
        if (priv == TRUE) {
            fclose(fp2);
            continue;
        }

        if (size <= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL)) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Improper size of object %s (ignoring it)\n",
                       fname);
            continue;
        }

        size -= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);
        buf = (CK_BYTE *) malloc(size);
        if (!buf) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot malloc %u bytes to read in "
                       "token object %s (ignoring it)", size, fname);
            continue;
        }

        read_size = fread(buf, 1, size, fp2);
        if (read_size != size) {
            fclose(fp2);
            free(buf);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot read token object %s " "(ignoring it)", fname);
            continue;
        }
        // ... grab object mutex here.
        if (object_mgr_restore_obj_withSize(tokdata,
                                            buf, NULL, size, fname) != CKR_OK) {
            OCK_SYSLOG(LOG_ERR,
                       "Cannot restore token object %s "
                       "(ignoring it)", fname);
        }
        free(buf);
        fclose(fp2);
    }

    fclose(fp1);

    return CKR_OK;
}


/******************************************************************************
 * tokversion >= 3.12 object store
 */

static CK_RV aes_256_gcm_seal(STDLL_TokData_t *tokdata,
                              unsigned char *out,
                              unsigned char tag[16],
                              const unsigned char *aad,
                              size_t aadlen,
                              const unsigned char *in,
                              size_t inlen,
                              const unsigned char key[32],
                              const unsigned char iv[12])
{
    CK_RV rc;
    int outlen;

    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, -1) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1
        || EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1) != 1
        || EVP_CipherUpdate(ctx, NULL, &outlen, aad, aadlen) != 1
        || EVP_CipherUpdate(ctx, out, &outlen, in, inlen) != 1
        || EVP_CipherFinal_ex(ctx, out + outlen, &outlen) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    rc = CKR_OK;

    if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id,
                                            &tokdata->store_strength.mk_crypt,
                                            tokdata->store_strength.mk_strength);

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static CK_RV aes_256_gcm_unseal(STDLL_TokData_t *tokdata,
                                unsigned char *out,
                                const unsigned char *aad,
                                size_t aadlen,
                                const unsigned char *in,
                                size_t inlen,
                                const unsigned char tag[16],
                                const unsigned char key[32],
                                const unsigned char iv[12])
{
    CK_RV rc;
    int outlen;

    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, -1) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *)tag) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1
        || EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0) != 1
        || EVP_CipherUpdate(ctx, NULL, &outlen, aad, aadlen) != 1
        || EVP_CipherUpdate(ctx, out, &outlen, in, inlen) != 1
        || EVP_CipherFinal_ex(ctx, out + outlen, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    rc = CKR_OK;

    if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id,
                                            &tokdata->store_strength.mk_crypt,
                                            tokdata->store_strength.mk_strength);

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static CK_RV aes_256_wrap(STDLL_TokData_t *tokdata,
                          unsigned char out[40],
                          const unsigned char in[32],
                          const unsigned char kek[32])
{
    CK_RV rc;
    int outlen;
    unsigned char buffer[40 + EVP_MAX_BLOCK_LENGTH];

    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL, 1) != 1
        || EVP_CipherUpdate(ctx, buffer, &outlen, in, 32) != 1
        || EVP_CipherFinal_ex(ctx, buffer + outlen, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    memcpy(out, buffer, 40);
    rc = CKR_OK;

    if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id,
                                            &tokdata->store_strength.wrap_crypt,
                                            tokdata->store_strength.wrap_strength);

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static CK_RV aes_256_unwrap(STDLL_TokData_t *tokdata,
                            unsigned char key[32],
                            const unsigned char in[40],
                            const unsigned char kek[32])
{
    CK_RV rc;
    int outlen;
    unsigned char buffer[32 + EVP_MAX_BLOCK_LENGTH];

    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL, 0) != 1
        || EVP_CipherUpdate(ctx, buffer, &outlen, in, 40) != 1
        || EVP_CipherFinal_ex(ctx, buffer + outlen, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    memcpy(key, buffer, 32);
    rc = CKR_OK;

    if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id,
                                            &tokdata->store_strength.wrap_crypt,
                                            tokdata->store_strength.wrap_strength);

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV generate_master_key(STDLL_TokData_t *tokdata, CK_BYTE *key)
{
    CK_RV rc;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return generate_master_key_old(tokdata, key);

    /* generate a 256-bit AES key */
    rc = rng_generate(tokdata, key, 32);

    if (rc == CKR_OK &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id,
                                            &tokdata->store_strength.mk_keygen,
                                            tokdata->store_strength.mk_strength);

    return rc;

}

/**
 * Wrap 256-bit AES master key by 256-bit AES SO wrap key
 * using AES-KW (RFC 3394). The resulting 40-bytes cipher-text
 * is stored in the MK_SO file in the token's data store.
 */
CK_RV save_masterkey_so(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    char fname[PATH_MAX];
    CK_RV rc;
    unsigned char outbuf[40];

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return save_masterkey_so_old(tokdata);

    /* Skip it if master key is not needed. */
    if (!token_specific.data_store.use_master_key)
        return CKR_OK;

    /* wrap master key with so_wrap_key */
    rc = aes_256_wrap(tokdata, outbuf, tokdata->master_key,
                      tokdata->so_wrap_key);
    if (rc != CKR_OK)
        goto done;

    // write the file
    //
    // probably ought to ensure the permissions are correct
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_SO",
                                    "w");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fwrite(outbuf, sizeof(outbuf), 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fwrite failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;
done:
    if (fp)
        fclose(fp);
    return rc;
}

CK_RV load_masterkey_so(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    CK_RV rc;
    char fname[PATH_MAX];
    unsigned char inbuf[40];

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return load_masterkey_so_old(tokdata);

    memset(tokdata->master_key, 0, sizeof(tokdata->master_key));

    // this file gets created on C_InitToken so we can assume that it always
    // exists
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_SO",
                                    "r");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fread(inbuf, sizeof(inbuf), 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fread() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* unwrap master key with so_wrap_key */
    rc = aes_256_unwrap(tokdata, tokdata->master_key, inbuf,
                        tokdata->so_wrap_key);
    if (rc != CKR_OK)
        goto done;

    rc = CKR_OK;
done:
    if (fp)
        fclose(fp);
    return rc;
}

/**
 * Wrap 256-bit AES master key by 256-bit AES User wrap key
 * using AES-KW (RFC 3394). The resulting 40-bytes cipher-text
 * is stored in the MK_SO file in the token's data store.
 */
CK_RV save_masterkey_user(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    char fname[PATH_MAX];
    CK_RV rc;
    unsigned char outbuf[40];

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return save_masterkey_user_old(tokdata);

    /* wrap master key with so_wrap_key */
    rc = aes_256_wrap(tokdata, outbuf, tokdata->master_key,
                      tokdata->user_wrap_key);
    if (rc != CKR_OK)
        goto done;

    // write the file
    //
    // probably ought to ensure the permissions are correct
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_USER",
                                    "w");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fwrite(outbuf, sizeof(outbuf), 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fwrite failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;
done:
    if (fp)
        fclose(fp);
    return rc;
}

CK_RV load_masterkey_user(STDLL_TokData_t *tokdata)
{
    FILE *fp = NULL;
    CK_RV rc;
    char fname[PATH_MAX];
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char inbuf[40];

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return load_masterkey_user_old(tokdata);

    memset(tokdata->master_key, 0, sizeof(tokdata->master_key));

    // this file gets created on C_InitToken so we can assume that it always
    // exists
    //
    fp = open_token_data_store_path(fname, sizeof(fname), tokdata, "MK_USER",
                                    "r");
    if (!fp) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    rc = fread(inbuf, sizeof(inbuf), 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fread failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* unwrap master key with user_wrap_key */
    rc = aes_256_unwrap(tokdata, tokdata->master_key, inbuf,
                        tokdata->user_wrap_key);
    if (rc != CKR_OK)
        goto done;

    rc = CKR_OK;
done:
    if (fp)
        fclose(fp);
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV save_token_data(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
    FILE *fp = NULL;
    TOKEN_DATA td;
    CK_RV rc;
    char fname[PATH_MAX];

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return save_token_data_old(tokdata, slot_id);

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        goto out_nolock;
    }

    fp = open_token_nvdat(fname, sizeof(fname), tokdata, "w");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    /* Write generic token data */
    memcpy(&td, tokdata->nv_token_data, sizeof(TOKEN_DATA));

    td.token_info.flags = htobe32(td.token_info.flags);
    td.token_info.ulMaxSessionCount = htobe32(td.token_info.ulMaxSessionCount);
    td.token_info.ulSessionCount = htobe32(td.token_info.ulSessionCount);
    td.token_info.ulMaxRwSessionCount
      = htobe32(td.token_info.ulMaxRwSessionCount);
    td.token_info.ulRwSessionCount = htobe32(td.token_info.ulRwSessionCount);
    td.token_info.ulMaxPinLen = htobe32(td.token_info.ulMaxPinLen);
    td.token_info.ulMinPinLen = htobe32(td.token_info.ulMinPinLen);
    td.token_info.ulTotalPublicMemory
      = htobe32(td.token_info.ulTotalPublicMemory);
    td.token_info.ulFreePublicMemory
      = htobe32(td.token_info.ulFreePublicMemory);
    td.token_info.ulTotalPrivateMemory
      = htobe32(td.token_info.ulTotalPrivateMemory);
    td.token_info.ulFreePrivateMemory
      = htobe32(td.token_info.ulFreePrivateMemory);
    td.tweak_vector.allow_weak_des = htobe32(td.tweak_vector.allow_weak_des);
    td.tweak_vector.check_des_parity
      = htobe32(td.tweak_vector.check_des_parity);
    td.tweak_vector.allow_key_mods = htobe32(td.tweak_vector.allow_key_mods);
    td.tweak_vector.netscape_mods = htobe32(td.tweak_vector.netscape_mods);
    td.dat.version = htobe32(td.dat.version);
    td.dat.so_login_it = htobe64(td.dat.so_login_it);
    td.dat.user_login_it = htobe64(td.dat.user_login_it);
    td.dat.so_wrap_it = htobe64(td.dat.so_wrap_it);
    td.dat.user_wrap_it = htobe64(td.dat.user_wrap_it);

    if (!fwrite(&td, sizeof(TOKEN_DATA), 1, fp)) {
        TRACE_ERROR("fwrite(%s): %s\n", fname,
                    ferror(fp) ? strerror(errno) : "failed");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Write token-specific data */
    if (token_specific.t_save_token_data) {
        rc = token_specific.t_save_token_data(tokdata, slot_id, fp);
        if (rc)
            goto done;
    }

    rc = CKR_OK;

done:
    if (fp)
        fclose(fp);

    if (rc == CKR_OK) {
        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK)
            TRACE_ERROR("Failed to release Process Lock.\n");
    } else {
        /* return error that occurred first */
        XProcUnLock(tokdata);
    }

out_nolock:
    return rc;
}

CK_RV load_token_data(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
    FILE *fp = NULL;
    char fname[PATH_MAX];
    TOKEN_DATA td;
    CK_RV rc;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return load_token_data_old(tokdata, slot_id);

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        goto out_nolock;
    }

    fp = open_token_nvdat(fname, sizeof(fname), tokdata, "r");
    if (!fp) {
        /* Better error checking added */
        if (errno == ENOENT) {
            init_token_data(tokdata, slot_id);

            fp = fopen(fname, "r");
            if (!fp) {
                // were really hosed here since the created
                // did not occur
                TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
                rc = CKR_FUNCTION_FAILED;
                goto out_unlock;
            }
        } else {
            /* Could not open file for some unknown reason */
            TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            goto out_unlock;
        }
    }
    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto out_unlock;

    /* Load generic token data */
    if (fread(&td, sizeof(TOKEN_DATA), 1, fp) != 1) {
        TRACE_ERROR("fread(%s): %s\n", fname,
                    ferror(fp) ? strerror(errno) : "failed");
        rc = CKR_FUNCTION_FAILED;
        goto out_unlock;
    }
    /* data marshalling */
    td.token_info.flags = be32toh(td.token_info.flags);
    td.token_info.ulMaxSessionCount = be32toh(td.token_info.ulMaxSessionCount);
    td.token_info.ulSessionCount = be32toh(td.token_info.ulSessionCount);
    td.token_info.ulMaxRwSessionCount
      = be32toh(td.token_info.ulMaxRwSessionCount);
    td.token_info.ulRwSessionCount = be32toh(td.token_info.ulRwSessionCount);
    td.token_info.ulMaxPinLen = be32toh(td.token_info.ulMaxPinLen);
    td.token_info.ulMinPinLen = be32toh(td.token_info.ulMinPinLen);
    td.token_info.ulTotalPublicMemory
      = be32toh(td.token_info.ulTotalPublicMemory);
    td.token_info.ulFreePublicMemory
      = be32toh(td.token_info.ulFreePublicMemory);
    td.token_info.ulTotalPrivateMemory
      = be32toh(td.token_info.ulTotalPrivateMemory);
    td.token_info.ulFreePrivateMemory
      = be32toh(td.token_info.ulFreePrivateMemory);
    td.tweak_vector.allow_weak_des = be32toh(td.tweak_vector.allow_weak_des);
    td.tweak_vector.check_des_parity
      = be32toh(td.tweak_vector.check_des_parity);
    td.tweak_vector.allow_key_mods = be32toh(td.tweak_vector.allow_key_mods);
    td.tweak_vector.netscape_mods = be32toh(td.tweak_vector.netscape_mods);
    td.dat.version = be32toh(td.dat.version);
    td.dat.so_login_it = be64toh(td.dat.so_login_it);
    td.dat.user_login_it = be64toh(td.dat.user_login_it);
    td.dat.so_wrap_it = be64toh(td.dat.so_wrap_it);
    td.dat.user_wrap_it = be64toh(td.dat.user_wrap_it);

    memcpy(tokdata->nv_token_data, &td, sizeof(TOKEN_DATA));

    /* Load token-specific data */
    if (token_specific.t_load_token_data) {
        rc = token_specific.t_load_token_data(tokdata, slot_id, fp);
        if (rc)
            goto out_unlock;
    }

    rc = CKR_OK;

out_unlock:
    if (fp)
        fclose(fp);

    if (rc == CKR_OK) {
        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK)
            TRACE_ERROR("Failed to release Process Lock.\n");
    } else {
        /* return error that occurred first */
        XProcUnLock(tokdata);
    }

out_nolock:
    return rc;
}

/**
 * Big-endian increment. Return carry.
 */
static inline int inc32(unsigned char ctr[4])
{
    unsigned int c = 1;

    c += (unsigned int)ctr[3];
    ctr[3] = (unsigned char)c;
    c >>= 8;
    c += (unsigned int)ctr[2];
    ctr[2] = (unsigned char)c;
    c >>= 8;
    c += (unsigned int)ctr[1];
    ctr[1] = (unsigned char)c;
    c >>= 8;
    c += (unsigned int)ctr[0];
    ctr[0] = (unsigned char)c;
    c >>= 8;

    return c;
}

/**
 * private tok obj layout
 *
 * --- auth -------           <--+
 * u32 tokversion                | 64-byte header
 * u8  private_flag              |
 * u8  reserved[3]               |
 * u8  key_wrapped[40]           |
 * u8  iv[12]                    |
 * u32 object_len                |
 * --- auth+enc ---           <--+
 * u8  object[object_len]        | body
 * ----------------           <--+
 * u8 tag[16]                    | 16-byte footer
 * ----------------           <--+
 */
#define HEADER_LEN  64
#define FOOTER_LEN  16

/**
 * public tok obj layout
 *
 * ----------------           <--+
 * u32 tokversion                | 16-byte header
 * u8  private_flag              |
 * u8  reserved[7]               |
 * u32 object_len                |
 * ----------------           <--+
 * u8  object[object_len]        | body
 * ----------------           <--+
 */
#define PUB_HEADER_LEN     16
#define HEADER_COMMON_LEN  5

//
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV save_private_token_object(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    FILE *fp = NULL;
    CK_BYTE *obj_data = NULL;
    char fname[PATH_MAX];
    struct stat sb;
    CK_ULONG obj_data_len;
    CK_RV rc;
    CK_ULONG_32 obj_data_len_32;
    CK_ULONG_32 total_len;
    CK_BBOOL flag = CK_TRUE;
    unsigned char obj_key[256 / 8], obj_iv[96 / 8], obj_key_wrapped[40];
    unsigned char *data = NULL;
    uint32_t tmp;
    int new = 0;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return save_private_token_object_old(tokdata, obj);

    sprintf(fname, "%s/%s/", tokdata->data_store, PK_LITE_OBJ_DIR);
    strncat(fname, (char *)obj->name, 8);

    rc = object_flatten(obj, &obj_data, &obj_data_len);
    obj_data_len_32 = obj_data_len;
    if (rc != CKR_OK) {
        goto done;
    }

    total_len = HEADER_LEN + obj_data_len_32 + FOOTER_LEN;

    data = malloc(total_len);
    if (data == NULL) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    fp = fopen(fname, "r");
    if (fp == NULL) {
        /* create new token object */
        new = 1;
    } else {
        if (fstat(fileno(fp), &sb) != 0) {
            TRACE_ERROR("fstat(%s): %s\n", fname, strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        /* New token objects files created by mkstemp have a size of zero */
        if (sb.st_size == 0) {
            new = 1;
            fclose(fp);
            fp = NULL;
            goto do_work;
        }

        /* update existing token object */
        if (fread(data, HEADER_LEN, 1, fp) != 1) {
            TRACE_ERROR("fread(%s): %s\n", fname, strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        fclose(fp);
        fp = NULL;

        /* iv */
        memcpy(obj_iv, data + 48, 12);

        /* increment iv counter field */
        if (inc32(obj_iv + 8)) {
            /* counter overflow: generate new key */
            new = 1;
        } else {
            /* get wrapped key key */
            memcpy(obj_key_wrapped, data + 8, 40);

            /* get key */
            rc = aes_256_unwrap(tokdata, obj_key, obj_key_wrapped,
                                tokdata->master_key);
            if (rc != CKR_OK)
                goto done;
        }
    }
do_work:
    if (new) {
        /* get key */
        rng_generate(tokdata, obj_key, 32);

        /* iv = [obj.-name|counter] */
        memcpy(obj_iv, obj->name, 8);
        obj_iv[8] = 0;
        obj_iv[9] = 0;
        obj_iv[10] = 0;
        obj_iv[11] = 1;

        /* get wrapped key */
        rc = aes_256_wrap(tokdata, obj_key_wrapped, obj_key,
                          tokdata->master_key);
        if (rc != CKR_OK)
            goto done;
    }

    /* version */
    tmp = htobe32(tokdata->version);
    memcpy(data, &tmp, 4);
    /* flags */
    memcpy(data + 4, &flag, 1);
    tmp = 0;
    memcpy(data + 5, &tmp, 3);
    /* wrapped key */
    memcpy(data + 8, obj_key_wrapped, 40);
    /* iv */
    memcpy(data + 48, obj_iv, 12);
    /* object len */
    tmp = htobe32(obj_data_len_32);
    memcpy(data + 60, &tmp, 4);

    rc = aes_256_gcm_seal(tokdata,
                          /* ciphertext */
                          data + HEADER_LEN,
                          /* tag */
                          data + HEADER_LEN
                               + obj_data_len_32,
                          /* aad */
                          data, HEADER_LEN,
                          /* plaintext */
                          obj_data, obj_data_len_32,
                          /* key */
                          obj_key,
                          /* iv */
                          obj_iv);
    if (rc != CKR_OK)
        goto done;

    fp = fopen(fname, "w");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    if (fwrite(data, total_len, 1, fp) != 1) {
        TRACE_ERROR("fwrite(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    fclose(fp);
    fp = NULL;

    rc = CKR_OK;
done:
    if (fp)
        fclose(fp);
    if (obj_data)
        free(obj_data);
    if (data)
        free(data);
    return rc;
}

//
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV load_private_token_objects(STDLL_TokData_t *tokdata)
{
    FILE *fp1 = NULL, *fp2 = NULL;
    CK_BYTE *buf = NULL;
    char tmp[PATH_MAX];
    char iname[PATH_MAX];
    char fname[PATH_MAX];
    CK_BBOOL priv;
    CK_ULONG_32 size;
    CK_RV rc;
    unsigned char header[HEADER_LEN], footer[FOOTER_LEN];
    uint32_t len;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return load_private_token_objects_old(tokdata);

    fp1 = open_token_object_index(iname, sizeof(iname), tokdata, "r");
    if (!fp1)
        return CKR_OK;          // no token objects

    while (fgets(tmp, 50, fp1)) {
        tmp[strlen(tmp) - 1] = 0;

        fp2 = open_token_object_path(fname, sizeof(fname), tokdata, tmp,"r");
        if (!fp2)
            continue;

        if (fread(header, HEADER_LEN, 1, fp2) != 1) {
            fclose(fp2);
            continue;
        }

        memcpy(&priv, header + 4, 1);
        if (priv == FALSE) {
            fclose(fp2);
            continue;
        }

        memcpy(&len, header + 60, 4);
        size = be32toh(len);

        buf = (CK_BYTE *)malloc(size);
        if (!buf) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot malloc %u bytes to read in "
                       "token object %s (ignoring it)", size, fname);
            continue;
        }

        if (fread(buf, size, 1, fp2) != 1) {
            free(buf);
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot read token object %s " "(ignoring it)", fname);
            continue;
        }
        if (fread(footer, FOOTER_LEN, 1, fp2) != 1) {
            free(buf);
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot read token object %s " "(ignoring it)", fname);
            continue;
        }

        rc = restore_private_token_object(tokdata, header,
                                          buf, size,
                                          footer, NULL, fname);
        if (rc != CKR_OK)
            goto error;

        free(buf);
        fclose(fp2);
    }

    fclose(fp1);
    return CKR_OK;
error:
    if (buf)
        free(buf);
    if (fp1)
        fclose(fp1);
    if (fp2)
        fclose(fp2);
    return rc;
}

//
//
CK_RV restore_private_token_object(STDLL_TokData_t *tokdata,
                                   CK_BYTE *header,
                                   CK_BYTE *data, CK_ULONG len,
                                   CK_BYTE *footer,
                                   OBJECT *pObj,
                                   const char *fname)
{
    unsigned char obj_iv[12], obj_key[32], obj_key_wrapped[40];
    CK_BYTE *buff = NULL;
    CK_RV rc;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return restore_private_token_object_old(tokdata, data, len, pObj,
                                                fname);

    /* wrapped key */
    memcpy(obj_key_wrapped, header + 8, 40);
    /* iv */
    memcpy(obj_iv, header + 48, 12);

    rc = aes_256_unwrap(tokdata, obj_key, obj_key_wrapped, tokdata->master_key);
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    buff = (CK_BYTE *)malloc(len);
    if (buff == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = aes_256_gcm_unseal(tokdata,
                            buff, /* plain-text */
                            header, HEADER_LEN, /* aad */
                            data, len, /* cipher-text*/
                            footer, /* tag */
                            obj_key, obj_iv);
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = object_mgr_restore_obj(tokdata, buff, pObj, fname);
    if (rc != CKR_OK) {
        goto done;
    }

    rc = CKR_OK;
done:
    if (buff)
        free(buff);
    return rc;
}

CK_RV reload_token_object(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    unsigned char header[HEADER_LEN], footer[FOOTER_LEN];
    FILE *fp = NULL;
    CK_BYTE *buf = NULL;
    char fname[PATH_MAX];
    CK_BBOOL priv;
    CK_ULONG_32 size;
    CK_ULONG size_64;
    CK_RV rc;
    uint32_t len;
    uint32_t ver;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return reload_token_object_old(tokdata, obj);

    memset(fname, 0x0, sizeof(fname));
    sprintf(fname, "%s/%s/", tokdata->data_store, PK_LITE_OBJ_DIR);
    strncat(fname, (char *) obj->name, 8);

    fp = fopen(fname, "r");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    if (fread(header, HEADER_COMMON_LEN, 1, fp) != 1) {
        OCK_SYSLOG(LOG_ERR, "Cannot read header\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    memcpy(&ver, header, 4);
    memcpy(&priv, header + 4, 1);
    if (priv) {
        if (fread(header + HEADER_COMMON_LEN,
                  HEADER_LEN - HEADER_COMMON_LEN, 1, fp) != 1) {
            OCK_SYSLOG(LOG_ERR, "Cannot read header\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        memcpy(&len, header + 60, 4);
    } else {
        if (fread(header + HEADER_COMMON_LEN,
                  PUB_HEADER_LEN - HEADER_COMMON_LEN, 1, fp) != 1) {
            OCK_SYSLOG(LOG_ERR, "Cannot read header\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        memcpy(&len, header + 12, 4);
    }

    /*
     * In OCK 3.12 - 3.14 the version and size was not stored in BE. So if
     * version field is in platform endianness, keep size as is also.
     */
    if (ver == TOK_NEW_DATA_STORE)
        size = len;
    else
        size = be32toh(len);

    buf = (CK_BYTE *) malloc(size);
    if (buf == NULL) {
        rc = CKR_HOST_MEMORY;
        OCK_SYSLOG(LOG_ERR,
                   "Cannot malloc %u bytes to read in token object %s "
                   "(ignoring it)", size, fname);
        goto done;
    }

    if (fread(buf, size, 1, fp) != 1) {
        OCK_SYSLOG(LOG_ERR,
                   "Token object %s appears corrupted (ignoring it)", fname);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (priv) {
        if (fread(footer, FOOTER_LEN, 1, fp) != 1) {
            OCK_SYSLOG(LOG_ERR,
                       "Token object %s appears corrupted (ignoring it)", fname);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    size_64 = size;

    if (priv) {
        rc = restore_private_token_object(tokdata, header, buf, size_64,
                                          footer, obj, fname);
    } else {
        rc = object_mgr_restore_obj(tokdata, buf, obj, fname);
    }
done:
    if (fp)
        fclose(fp);
    if (buf)
        free(buf);
    return rc;
}

//
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV save_public_token_object(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    FILE *fp = NULL;
    CK_BYTE *clear = NULL;
    char fname[PATH_MAX];
    CK_ULONG clear_len;
    CK_BBOOL flag = FALSE;
    CK_RV rc;
    CK_ULONG_32 len, be_len;
    unsigned char reserved[7] = {0};
    uint32_t tmp;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return save_public_token_object_old(tokdata, obj);

    rc = object_flatten(obj, &clear, &clear_len);
    if (rc != CKR_OK) {
        goto done;
    }
    len = (CK_ULONG_32)clear_len;

    sprintf(fname, "%s/%s/", tokdata->data_store, PK_LITE_OBJ_DIR);
    strncat(fname, (char *) obj->name, 8);

    fp = fopen(fname, "w");
    if (!fp) {
        TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    tmp = htobe32(tokdata->version);
    be_len = htobe32(len);

    rc = set_perm(fileno(fp), tokdata->tokgroup);
    if (rc != CKR_OK)
        goto done;

    if (fwrite(&tmp, 4, 1, fp) != 1
        || fwrite(&flag, 1, 1, fp) != 1
        || fwrite(reserved, 7, 1, fp) != 1
        || fwrite(&be_len, 4, 1, fp) != 1
        || fwrite(clear, len, 1, fp) != 1) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    fclose(fp);
    fp = NULL;

    rc = CKR_OK;
done:
    if (fp)
        fclose(fp);
    if (clear)
        free(clear);
    return rc;
}

//
// Note: The token lock (XProcLock) must be held when calling this function.
//
CK_RV load_public_token_objects(STDLL_TokData_t *tokdata)
{
    FILE *fp1 = NULL, *fp2 = NULL;
    CK_BYTE *buf = NULL;
    char tmp[PATH_MAX];
    char iname[PATH_MAX];
    char fname[PATH_MAX];
    CK_BBOOL priv;
    CK_ULONG_32 size;
    unsigned char header[PUB_HEADER_LEN];
    uint32_t ver;

    if (tokdata->version < TOK_NEW_DATA_STORE)
        return load_public_token_objects_old(tokdata);

    fp1 = open_token_object_index(iname, sizeof(iname), tokdata, "r");
    if (!fp1)
        return CKR_OK;          // no token objects

    while (fgets(tmp, 50, fp1)) {
        tmp[strlen(tmp) - 1] = 0;

        sprintf(fname, "%s/%s/", tokdata->data_store, PK_LITE_OBJ_DIR);
        strcat(fname, tmp);

        fp2 = fopen(fname, "r");
        if (!fp2)
            continue;

        if (fread(header, PUB_HEADER_LEN, 1, fp2) != 1) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Cannot read header\n");
            continue;
        }

        memcpy(&ver, header, 4);
        memcpy(&priv, header + 4, 1);
        memcpy(&size, header + 12, 4);

        /*
         * In OCK 3.12 - 3.14 the version and size was not stored in BE. So if
         * version field is in platform endianness, keep size as is also
         */
        if (ver != TOK_NEW_DATA_STORE)
            size = be32toh(size);

        if (priv == TRUE) {
            fclose(fp2);
            continue;
        }

        /* size can not be negative if treated as signed int */
        if (size >= 0x80000000) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR, "Size is invalid in header of token object %s "
                                "(ignoring it)\n", fname);
            continue;
        }

        buf = (CK_BYTE *) malloc(size);
        if (!buf) {
            fclose(fp2);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot malloc %u bytes to read in "
                       "token object %s (ignoring it)", size, fname);
            continue;
        }

        if (fread(buf, size, 1, fp2) != 1) {
            fclose(fp2);
            free(buf);
            OCK_SYSLOG(LOG_ERR,
                       "Cannot read token object %s " "(ignoring it)", fname);
            continue;
        }
        // ... grab object mutex here.
        if (object_mgr_restore_obj_withSize(tokdata,
                                            buf, NULL, size, fname) != CKR_OK) {
            OCK_SYSLOG(LOG_ERR,
                       "Cannot restore token object %s "
                       "(ignoring it)", fname);
        }
        free(buf);
        fclose(fp2);
    }

    fclose(fp1);
    return CKR_OK;
}
