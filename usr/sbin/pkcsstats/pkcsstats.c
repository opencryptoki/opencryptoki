/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * pkcsstats - A tool to display mechanism usage statistics.
 *
 */

#include "platform.h"
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <pwd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <pkcs11types.h>

#if defined(_AIX)
    #include <libgen.h>
    const char *__progname = "pkcsstats";
#endif

#include "platform.h"
#include "statistics.h"
#include "p11util.h"

#define UNUSED(var)            ((void)(var))

static void usage(char *progname)
{
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Display mechanism usage statistics for openCryptoki.\n\n");
    printf("OPTIONS:\n");
    printf(" -U, --user USERID  show the statistics from one user. (root user only)\n");
    printf(" -S, --summary      show the accumulated statistics from all users. (root user only)\n");
    printf(" -A, --all          show the statistic tables from all users. (root user only)\n");
    printf(" -a, --all-mechs    show all mechanisms, also those with all zero counters.\n");
    printf(" -s, --slot SLOTID  show the statistics from one slot only.\n");
    printf(" -r, --reset        set the own statistics to zero.\n");
    printf(" -R, --reset-all    reset the statistics from all users. (root user only)\n");
    printf(" -d, --delete       delete your own statistics.\n");
    printf(" -D, --delete-all   delete the statistics from all users. (root user only)\n");
    printf(" -j, --json         output the statistics in JSON format.\n");
    printf(" -h, --help         display help information.\n");

    return;
}

static void make_shm_name(char *shm_name, size_t max_shm_len, int user_id)
{
    int i;

    if (user_id == -1)
        snprintf(shm_name, max_shm_len - 1, "%s_stats", CONFIG_PATH);
    else
        snprintf(shm_name, max_shm_len - 1, "%s_stats_%d", CONFIG_PATH,
                 user_id);

    for (i = 1; shm_name[i] != '\0'; i++) {
        if (shm_name[i] == '/')
            shm_name[i] = '.';
    }
    if (shm_name[0] != '/') {
        memmove(&shm_name[1], &shm_name[0], strlen(shm_name) + 1);
        shm_name[0] = '/';
    }
}

static int open_shm(uid_t user_id, const char *user_name,
                    CK_ULONG num_slots, CK_BYTE **shm_data,
                    CK_ULONG *shm_size)
{
    char shm_name[PATH_MAX];
    struct stat stat_buf;
    int shm_fd;

    make_shm_name(shm_name, sizeof(shm_name), user_id);

    shm_fd = shm_open(shm_name, O_RDWR, S_IRUSR | S_IWUSR);
    if (shm_fd == -1) {
        if (errno == ENOENT)
            warnx("No statistics are available for user '%s'", user_name);
        else
            warnx("Failed to open statistics for user '%s': shm_open('%s'): %s",
                  user_name, shm_name, strerror(errno));
        return 1;
    }

    if (fstat(shm_fd, &stat_buf)) {
        warnx("Failed to open statistics for user '%s': stat('%s'): %s",
              user_name, shm_name, strerror(errno));
        close(shm_fd);
        return 1;
    }

    /*
     * If the shared memory segment does not belong to the user or does
     * not have correct permissions, do not use it.
     */
    if (stat_buf.st_uid != user_id ||
        (stat_buf.st_mode & ~S_IFMT) != (S_IRUSR | S_IWUSR)) {
        warnx("Failed to open statistics for user '%s': SHM '%s' has wrong mode/owner",
              user_name, shm_name);
        close(shm_fd);
        return 1;
    }

    *shm_size = num_slots * STAT_SLOT_SIZE;

    if ((CK_ULONG)stat_buf.st_size != *shm_size) {
        warnx("Failed to open statistics for user '%s': SHM '%s' has wrong size",
              user_name, shm_name);
        close(shm_fd);
        return 1;
    }

    *shm_data = (CK_BYTE *)mmap(NULL, *shm_size,
                                PROT_READ | PROT_WRITE, MAP_SHARED,
                                shm_fd, 0);
    close(shm_fd);
    if (*shm_data == MAP_FAILED) {
        warnx("Failed to open statistics for user '%s': mmap('%s'): %s",
              user_name, shm_name,  strerror(errno));
        return 1;
    }

    return 0;
}

static void close_shm(CK_BYTE *shm_data, CK_ULONG shm_size)
{
    if (shm_data == NULL)
         return;

     munmap(shm_data, shm_size);
}

typedef int (*user_f)(int user_id, const char *user_name, void *private);

static int for_all_users(user_f user_cb, void *cb_private)
{
#if defined(_AIX)
    return 0;
#else
    char shm_prefix[PATH_MAX];
    struct dirent *direntp;
    DIR *shmDir;
    struct passwd *pwd;
    int rc = 0, uid;
    char *endptr;

    make_shm_name(shm_prefix, sizeof(shm_prefix), -1);

    shmDir = opendir("/dev/shm");
    if (shmDir == NULL) {
        warnx("Failed to open /dev/shm: %s", strerror(errno));
        return 1;
    }

    while ((direntp = readdir(shmDir)) != NULL) {
        if(strstr(direntp->d_name, &shm_prefix[1]) != NULL) {
            errno = 0;
            uid = strtoul(&direntp->d_name[strlen(shm_prefix)], &endptr, 10);
            if ((errno == ERANGE && uid >= INT_MAX) ||
                (errno != 0 && uid == 0) || *endptr != '\0')
                continue;

            if((pwd = getpwuid(uid)) == NULL)
                continue;

            rc = user_cb(uid, pwd->pw_name, cb_private);
            if (rc != 0)
                break;
        }
    }

    closedir(shmDir);
    return rc;
#endif
}

typedef int (*slot_f)(CK_SLOT_ID slot_id, CK_BYTE *slot_data,
                      CK_ULONG slot_size, void *private);

static int for_all_slots(slot_f slot_cb, void *cb_private,
                         CK_BYTE *shm_data, CK_ULONG shm_size,
                         CK_ULONG num_slots, CK_SLOT_ID *slots,
                         bool slot_id_specified, CK_SLOT_ID slot_id)
{
    int rc = 0;
    CK_ULONG i;
    bool slot_found = false;

    for (i = 0; i < num_slots; i++) {
        if (slot_id_specified && slots[i] != slot_id)
             continue;

        slot_found = true;

        if ((i * STAT_SLOT_SIZE) + STAT_SLOT_SIZE > shm_size)
            break;

        rc = slot_cb(slots[i], &shm_data[i * STAT_SLOT_SIZE],  STAT_SLOT_SIZE,
                     cb_private);
        if (rc != 0)
            break;
    }

    if (slot_id_specified && !slot_found) {
        warnx("Slot %lu is not available", slot_id);
        return 1;
    }

    return rc;
}

static bool all_conters_zero(CK_BYTE *mech_data, CK_ULONG mech_size)
{
    counter_t *counter = (counter_t *)mech_data;
    int i;

    for (i = 0; i < NUM_SUPPORTED_STRENGTHS + 1 &&
                i * sizeof(counter_t) < mech_size; i++) {
        if (counter[i] != 0)
            return false;
    }

    return true;
}

typedef int (*mech_f)(CK_MECHANISM_TYPE mech, const char *mech_name,
                      CK_BYTE *mech_data, CK_ULONG mech_size,
                      CK_ULONG ofs, void *private);

static int for_each_mech(mech_f mech_cb, void *cb_private,
                         CK_BYTE *slot_data, CK_ULONG slot_size,
                         bool all_mechs)
{
    CK_ULONG i, ofs;
    int rc = -1;

    for (i = 0, ofs = 0; i < MECHTABLE_NUM_ELEMS; i++, ofs += STAT_MECH_SIZE) {
        if (ofs + STAT_MECH_SIZE > slot_size)
            break;

        if (!all_mechs && all_conters_zero(&slot_data[ofs], STAT_MECH_SIZE))
            continue;

        rc = mech_cb(mechtable_rows[i].numeric, mechtable_rows[i].string,
                     &slot_data[ofs], STAT_MECH_SIZE, ofs, cb_private);
        if (rc != 0)
            break;
    }

    return rc;
}

static int delete_shm(uid_t user_id, const char *user_name)
{
    char shm_name[PATH_MAX];
    int rc;

    make_shm_name(shm_name, sizeof(shm_name), user_id);
    rc = shm_unlink(shm_name);
    if (rc != 0) {
        if (errno == ENOENT)
            warnx("No statistics are available for user '%s'", user_name);
        else
            warnx("Failed to delete statistics for user '%s': shm_unlink('%s'): %s",
                  user_name, shm_name,  strerror(errno));
        return 1;
    }

    printf("Deleted statistics for user '%s'\n", user_name);

    return 0;
}

static int delete_all_cb(int user_id, const char *user_name, void *private)
{
    UNUSED(private);

    return delete_shm(user_id, user_name);
}

static int reset_slot_cb(CK_SLOT_ID slot_id, CK_BYTE *slot_data,
                         CK_ULONG slot_size, void *private)
{
    UNUSED(slot_id);
    UNUSED(private);

    memset(slot_data, 0, slot_size);

    return 0;
}

static int reset_shm(uid_t user_id, const char *user_name,
                     CK_ULONG num_slots, CK_SLOT_ID *slots,
                     bool slot_id_specified, CK_SLOT_ID slot_id)
{
    int rc = 0;
    CK_BYTE *shm_data = NULL;
    CK_ULONG shm_size = 0;

    rc = open_shm(user_id, user_name, num_slots, &shm_data, &shm_size);
    if (rc != 0)
        return rc;

    rc = for_all_slots(reset_slot_cb, NULL, shm_data, shm_size,
                       num_slots, slots, slot_id_specified, slot_id);

    if (rc == 0) {
        if (slot_id_specified)
            printf("Resetted statistics for user '%s' and slot %lu\n",
                   user_name, slot_id);
        else
            printf("Resetted statistics for user '%s'\n", user_name);
    }

    close_shm(shm_data, shm_size);
    return rc;
}

struct reset_data {
    CK_ULONG num_slots;
    CK_SLOT_ID *slots;
    bool slot_id_specified;
    CK_SLOT_ID slot_id;
};

static int reset_all_cb(int user_id, const char *user_name, void *private)
{
    struct reset_data *rd = (struct reset_data *)private;

    return reset_shm(user_id, user_name, rd->num_slots, rd->slots,
                     rd->slot_id_specified, rd->slot_id);
}

static int get_slot_infos(CK_FUNCTION_LIST_PTR func_list,
                          CK_SLOT_ID **slots, CK_ULONG *num_slots)
{
    CK_RV rc;

    rc = func_list->C_GetSlotList(FALSE, NULL, num_slots);
    if (rc != CKR_OK) {
        warnx("Error getting number of slots: 0x%lX (%s)\n", rc,
               p11_get_ckr(rc));
        return 1;
    }

    if (*num_slots == 0) {
        warnx("C_GetSlotList returned 0 slots. Check that your tokens"
               " are installed correctly.\n");
        return 1;
    }

    *slots = (CK_SLOT_ID_PTR) malloc(*num_slots * sizeof(CK_SLOT_ID));

    rc = func_list->C_GetSlotList(FALSE, *slots, num_slots);
    if (rc != CKR_OK) {
        warnx("Error getting slot list: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        return rc;
    }

    return 0;
}

int get_token_infos(CK_FUNCTION_LIST_PTR func_list, CK_SLOT_ID slot,
                    char *label, size_t label_len,
                    char *model, size_t model_len)
{
    CK_TOKEN_INFO info;
    CK_RV rc;
    int i;

    rc = func_list->C_GetTokenInfo(slot, &info);
    if (rc == CKR_TOKEN_NOT_PRESENT)
        return -1;
    if (rc != CKR_OK) {
        warnx("Error getting token infos for slot %lu: 0x%lX (%s)\n", slot, rc,
               p11_get_ckr(rc));
        return 1;
    }

    for (i = sizeof(info.label) - 1; i >= 0 && info.label[i] == ' '; i--)
        info.label[i] = '\0';
    for (i = sizeof(info.model) - 1; i >= 0 && info.model[i] == ' '; i--)
        info.model[i] = '\0';

    if (label_len > sizeof(info.label))
        label_len = sizeof(info.label);
    strncpy(label, (char*)info.label, label_len);
    label[label_len - 1] = '\0';

    if (model_len > sizeof(info.model))
        model_len = sizeof(info.model);
    strncpy(model, (char*)info.model, model_len);
    model[model_len - 1] = '\0';

    return 0;
}

struct display_mech {
    bool json;
    bool first_mech;
};

static int display_mech_cb(CK_MECHANISM_TYPE mech, const char *mech_name,
                           CK_BYTE *mech_data, CK_ULONG mech_size,
                           CK_ULONG ofs, void *private)
{
    counter_t *counter = (counter_t *)mech_data;
    struct display_mech *dm = private;
    int i;

    UNUSED(mech);
    UNUSED(ofs);

    if (dm->json && dm->first_mech == false)
        printf(",");

    if (dm->json)
        printf("\n\t\t\t\t\t\t{\n\t\t\t\t\t\t\t\"mechanism\": \"%s\",\n", mech_name);
    else
        printf("%-30s |", mech_name);

    for (i = 0; i < NUM_SUPPORTED_STRENGTHS + 1 &&
                 i * sizeof(counter_t) < mech_size; i++) {
        if (dm->json)
            printf("\t\t\t\t\t\t\t\"strength-%lu\": %lu%s\n",
                   i == 0 ? 0 : supportedstrengths[NUM_SUPPORTED_STRENGTHS - i],
                   counter[i], i == NUM_SUPPORTED_STRENGTHS ? "" : ",");
        else
            printf(" %15lu", counter[i]);
    }

    if (dm->json)
        printf("\t\t\t\t\t\t}");
    else
        printf("\n");
    dm->first_mech = false;

    return 0;
}

struct display_data {
    CK_FUNCTION_LIST *func_list;
    CK_ULONG num_slots;
    CK_SLOT_ID *slots;
    bool slot_id_specified;
    CK_SLOT_ID slot_id;
    bool all_mechs;
    bool json;
    bool first_user;
    bool first_slot;
};

static void print_horizontal_line(void)
{
    int i;

    printf("-------------------------------+");
    for (i = 0; i < NUM_SUPPORTED_STRENGTHS + 1; i++)
        printf("----------------");
    printf("-\n");
}

static void print_header(void)
{
    int i;

    print_horizontal_line();
    printf("mechanism                      | strength 0      ");
    for (i = 0; i < NUM_SUPPORTED_STRENGTHS; i++)
        printf("strength %-5lu  ",
               supportedstrengths[NUM_SUPPORTED_STRENGTHS - 1 - i]);
    printf("\n");
    printf("                               | or no key\n");
    print_horizontal_line();
}

static void print_footer(void)
{
    print_horizontal_line();
    printf("\n");
}


static int display_slot_stats(CK_FUNCTION_LIST *func_list, CK_SLOT_ID slot,
                              CK_BYTE *slot_data, CK_ULONG slot_size,
                              bool all_mechs, bool json, bool *first)
{
    char label[33], model[33];
    struct display_mech dm;
    int rc;

    rc = get_token_infos(func_list, slot, label, sizeof(label),
                         model, sizeof(model));
    if (rc > 0)
        return rc;

    if (json && *first == false)
        printf(",");
    if (json)
        printf("\n\t\t\t\t{\n\t\t\t\t\t\"slot\": %lu,\n", slot);

    if (rc == 0) {
        if (json) {
            printf("\t\t\t\t\t\"token-present\": true,\n");
            printf("\t\t\t\t\t\"label\": \"%s\",\n", label);
            printf("\t\t\t\t\t\"model\": \"%s\",\n", model);
        } else {
            printf("Slot: %lu (label: '%s' model: '%s')\n\n", slot, label,
                   model);
        }
    } else {
        if (json)
            printf("\t\t\t\t\t\"token-present\": false,\n");
        else
            printf("Slot: %lu (no token present)\n\n", slot);
    }

    if (json)
        printf("\t\t\t\t\t\"mechanisms\": [");
    else
        print_header();

    dm.json = json;
    dm.first_mech = true;
    rc = for_each_mech(display_mech_cb, &dm, slot_data, slot_size, all_mechs);
    if (rc < 0) {
        if (!json)
            printf("[no mechanisms were used]      |\n");
    } else if (rc != 0) {
        return rc;
    }

    if (json)
        printf("\n\t\t\t\t\t]\n\t\t\t\t}");
    else
        print_footer();

    *first = false;

    return 0;
}

static int display_slot_cb(CK_SLOT_ID slot_id, CK_BYTE *slot_data,
                           CK_ULONG slot_size, void *private)
{
    struct display_data *dd = private;

    return display_slot_stats(dd->func_list, slot_id, slot_data, slot_size,
                              dd->all_mechs, dd->json, &dd->first_slot);
}

static int display_stats(int user_id, const char *user_name,
                         struct display_data* dd)
{
    int rc = 0;
    CK_BYTE *shm_data = NULL;
    CK_ULONG shm_size = 0;

    rc = open_shm(user_id, user_name, dd->num_slots, &shm_data, &shm_size);
    if (rc != 0)
        return rc;

    if (dd->json) {
        if (!dd->first_user)
            printf(",\n");
        printf("\t\t{\n\t\t\t\"user\": \"%s\",\n\t\t\t\"slots\": [", user_name);
    } else {
        printf("User: %s\n\n", user_name);
    }

    dd->first_slot = true;
    rc = for_all_slots(display_slot_cb, dd, shm_data, shm_size,
                       dd->num_slots, dd->slots,
                       dd->slot_id_specified, dd->slot_id);

    if (dd->json)
        printf("\n\t\t\t]\n\t\t}");
    dd->first_user = false;

    close_shm(shm_data, shm_size);
    return rc;
}

static int display_all_cb(int user_id, const char *user_name, void *private)
{
    return display_stats(user_id, user_name, (struct display_data *)private);
}

struct summary_data {
    CK_ULONG num_slots;
    CK_SLOT_ID *slots;
    CK_BYTE *summary_data;
    CK_ULONG summary_size;
    CK_SLOT_ID slot_id;
};

static int summary_mech_cb(CK_MECHANISM_TYPE mech, const char *mech_name,
                           CK_BYTE *mech_data, CK_ULONG mech_size,
                           CK_ULONG ofs, void *private)
{
    struct summary_data *sd = private;
    counter_t *slot_counter = (counter_t *)mech_data;
    counter_t *sum_counter;
    int i;

    UNUSED(mech);
    UNUSED(mech_name);

    ofs += sd->slot_id * STAT_SLOT_SIZE;
    if (ofs + (NUM_SUPPORTED_STRENGTHS + 1) * sizeof(counter_t) >
                                                        sd->summary_size) {
        warnx("Internal error: mechanism offset larger than summary size");
        return 1;
    }

    sum_counter = (counter_t *)(&sd->summary_data[ofs]);

    for (i = 0; i < NUM_SUPPORTED_STRENGTHS + 1 &&
                i * sizeof(counter_t) < mech_size; i++)
        sum_counter[i] += slot_counter[i];

    return 0;
}

static int summary_slot_cb(CK_SLOT_ID slot_id, CK_BYTE *slot_data,
                           CK_ULONG slot_size, void *private)
{
    int rc;
    struct summary_data *sd = private;

    sd->slot_id = slot_id;

    rc = for_each_mech(summary_mech_cb, sd, slot_data, slot_size, true);

    return rc < 0 ? 0 : rc;
}

static int display_summary_cb(int user_id, const char *user_name, void *private)
{
    struct summary_data *sd = private;
    int rc = 0;
    CK_BYTE *shm_data = NULL;
    CK_ULONG shm_size = 0;

    rc = open_shm(user_id, user_name, sd->num_slots, &shm_data, &shm_size);
    if (rc != 0)
        return rc;

    rc = for_all_slots(summary_slot_cb, sd, shm_data, shm_size,
                       sd->num_slots, sd->slots, false, 0);

    close_shm(shm_data, shm_size);
    return rc;

}

static int display_summary(struct display_data* dd)
{
    struct summary_data sd;
    int rc = 0;

    sd.num_slots = dd->num_slots;
    sd.slots = dd->slots;
    sd.summary_size = dd->num_slots * STAT_SLOT_SIZE;
    sd.summary_data = calloc(sd.summary_size, 1);
    if (sd.summary_data == NULL) {
        warnx("Failed to allocate the summary buffer");
        return 1;
    }

    rc = for_all_users(display_summary_cb, &sd);
    if (rc != 0)
        goto done;

    if (dd->json) {
        if (!dd->first_user)
            printf(",\n");
        printf("\t\t{\n\t\t\t\"user\": \"(all users)\",\n\t\t\t\"slots\": [");
    } else {
        printf("Summary (all users):\n\n");
    }

    dd->first_slot = true;
    rc = for_all_slots(display_slot_cb, dd, sd.summary_data, sd.summary_size,
                       dd->num_slots, dd->slots,
                       dd->slot_id_specified, dd->slot_id);

    if (dd->json)
        printf("\n\t\t\t]\n\t\t}");

done:
    free(sd.summary_data);

    return rc;
}

int init_ock(void **dll, CK_FUNCTION_LIST_PTR *func_list)
{
    void (*sym_ptr)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV rc;

    *dll = dlopen(OCK_API_LIBNAME, DYNLIB_LDFLAGS);
    if (*dll == NULL) {
        warnx("Error loading PKCS#11 library: dlopen: %s", dlerror());
        return 1;
    }

    *(void **)(&sym_ptr) = dlsym(*dll, "C_GetFunctionList");
    if (sym_ptr == NULL) {
        warnx("Error loading PKCS#11 library: dlsym(C_GetFunctionList): %s",
              dlerror());
#ifndef WITH_SANITIZER
        dlclose(*dll);
#endif
        *dll = NULL;
        return 1;
    }

    sym_ptr(func_list);
    if (*func_list == NULL) {
        warnx("Error getting function list from PKCS11 library");
#ifndef WITH_SANITIZER
        dlclose(*dll);
#endif
        *dll = NULL;
        return 1;
    }

    rc = (*func_list)->C_Initialize(NULL);
    if (rc != CKR_OK) {
        warnx("Error initializing the PKCS11 library: 0x%lX (%s)", rc,
               p11_get_ckr(rc));
#ifndef WITH_SANITIZER
        dlclose(*dll);
#endif
        *dll = NULL;
        *func_list = NULL;
        return 1;
    }

    return 0;
}

static int print_json_start(void)
{
    char timestamp[200];
    struct utsname un;
    struct tm *tm;
    time_t t;

    time(&t);
    tm = gmtime(&t);
    /* ISO 8601 format: e.g. 2021-11-17T08:01:23Z (always UTC) */
    strftime(timestamp, sizeof(timestamp), "%FT%TZ", tm);

    if (uname(&un) != 0) {
        warnx("Failed to obtain system information, uname: %s",
               strerror(errno));
        return 1;
    }

    printf("{\n\t\"host\": {\n");
    printf("\t\t\"nodename\": \"%s\",\n", un.nodename);
    printf("\t\t\"sysname\": \"%s\",\n", un.sysname);
    printf("\t\t\"release\": \"%s\",\n", un.release);
    printf("\t\t\"machine\": \"%s\",\n", un.machine);
    printf("\t\t\"date\": \"%s\"\n", timestamp);
    printf("\t},\n\t\"users\": [\n");

    return 0;
}

int main(int argc, char **argv)
{
    int opt = 0;
    struct passwd *pswd = NULL;
    int user_id = -1;
    char *user_name = NULL;
    bool summary = false, all_users = false, all_mechs = false;
    bool reset = false, reset_all = false;
    bool delete = false, delete_all = false;
    bool slot_id_specified = false;
    bool json = false, json_started = false;
    CK_SLOT_ID slot_id = 0;
    void *dll = NULL;
    CK_FUNCTION_LIST *func_list = NULL;
    CK_ULONG num_slots = 0;
    CK_SLOT_ID *slots = NULL;
    char *endptr;
    int rc = 0;
    struct display_data dd;
    struct reset_data rd;

    static const struct option long_opts[] = {
        {"user", required_argument, NULL, 'U'},
        {"summary", no_argument, NULL, 'S'},
        {"all", no_argument, NULL, 'A'},
        {"all-mechs", no_argument, NULL, 'a'},
        {"slot", required_argument, NULL, 's'},
        {"reset", no_argument, NULL, 'r'},
        {"reset-all", no_argument, NULL, 'R'},
        {"delete", no_argument, NULL, 'd'},
        {"delete-all", no_argument, NULL, 'D'},
        {"json", no_argument, NULL, 'j'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "U:SAas:rRdDjh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'U':
            if ((pswd = getpwnam(optarg)) == NULL) {
                warnx("The username '%s' is not known on this system", optarg);
                return EXIT_FAILURE;
            }
            if(geteuid() != 0 && geteuid() != pswd->pw_uid) {
                warnx("You have no rights to display the statistics from other users");
                return EXIT_FAILURE;
            }
            user_id = pswd->pw_uid;
            break;
        case 'S':
#ifdef _AIX
            warnx("This option is unsupported on AIX; only showing statistics for current user.");
#else
            if (geteuid() != 0) {
                warnx("You have no rights to display the statistics from all users");
                return EXIT_FAILURE;
            }
            summary = true;
#endif
            break;
        case 'A':
#ifdef _AIX
            warnx("This option is unsupported on AIX; only using statistics for current user.");
#else
            if (geteuid() != 0) {
                warnx("You have no rights to display the statistics from all users");
                return EXIT_FAILURE;
            }
            all_users = true;
#endif
            break;
        case 'a':
            all_mechs = true;
            break;
        case 's':
            errno = 0;
            slot_id = strtoul(optarg, &endptr, 10);
            if ((errno == ERANGE && slot_id == ULONG_MAX) ||
                (errno != 0 && slot_id == 0)) {
                warnx("Slot parameter invalid: '%s'", optarg);
                exit(EXIT_FAILURE);
            }
            slot_id_specified = CK_TRUE;
            break;
        case 'r':
            reset = true;
            break;
        case 'R':
#ifdef _AIX
            warnx("This option is unsupported on AIX; only showing statistics for current user.");
#else
            if (geteuid() != 0) {
                warnx("You have no rights to reset the statistics from all users");
                return EXIT_FAILURE;
            }
            reset_all = true;
#endif
            break;
        case 'd':
            delete = true;
            break;
        case 'D':
#ifdef _AIX
            warnx("This option is unsupported on AIX; only showing statistics for current user.");
#else
            if (geteuid() != 0) {
                warnx("You have no rights to delete the statistics from all users");
                return EXIT_FAILURE;
            }
            delete_all = true;
#endif
            break;
        case 'j':
            json = true;
            break;
        case 'h':
            usage(basename(argv[0]));
            exit(EXIT_SUCCESS);
        default:
            exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        warnx("unrecognized option '%s'", argv[optind]);
        exit(EXIT_FAILURE);
    }

    if (user_id != -1 && all_users) {
        warnx("Options -u/--user and -A/--all can not be specified together");
        exit(EXIT_FAILURE);
    }

    if (user_id == -1) {
        user_id = geteuid();
        pswd = getpwuid(user_id);
        if (pswd == NULL) {
            warnx("Failed to get current user name");
            exit(EXIT_FAILURE);
        }
    }

    user_name = strdup(pswd->pw_name);
    if (user_name == NULL) {
        warnx("Failed to get current user name");
        exit(EXIT_FAILURE);
    }

    if (delete) {
        if (slot_id_specified) {
            warnx("Options -s/--slot and -d/--delete can not be specified together");
            free(user_name);
            exit(EXIT_FAILURE);
        }

        rc = delete_shm(user_id, user_name);
        goto done;
    }

    if (delete_all) {
        if (slot_id_specified) {
            warnx("Options -s/--slot and -D/--delete-all can not be specified together");
            free(user_name);
            exit(EXIT_FAILURE);
        }

        rc = for_all_users(delete_all_cb, NULL);
        goto done;
    }

    rc = init_ock(&dll, &func_list);
    if (rc != 0)
        goto done;

    rc = get_slot_infos(func_list, &slots, &num_slots);
    if (rc != 0)
        goto done;

    if (reset) {
        rc = reset_shm(user_id, user_name, num_slots, slots,
                       slot_id_specified, slot_id);
        goto done;
    }

    if (reset_all) {
        rd.num_slots = num_slots;
        rd.slots = slots;
        rd.slot_id_specified = slot_id_specified;
        rd.slot_id = slot_id;

        rc = for_all_users(reset_all_cb, &rd);
        goto done;
    }

    if (json) {
        if (print_json_start() != 0)
            goto done;
        json_started = true;
    }

    dd.func_list = func_list;
    dd.num_slots = num_slots;
    dd.slots = slots;
    dd.slot_id_specified = slot_id_specified;
    dd.slot_id = slot_id;
    dd.all_mechs = all_mechs;
    dd.json = json;
    dd.first_user = true;
    if (all_users) {
        rc = for_all_users(display_all_cb, &dd);
        goto done;
    } else if (summary) {
        rc = display_summary(&dd);
        goto done;
    } else {
        rc = display_stats(user_id, user_name, &dd);
        goto done;
    }

done:
    if (json && json_started)
        printf("\n\t]\n}\n");

    if (slots != NULL)
        free(slots);

    if (dll != NULL) {
        func_list->C_Finalize(NULL);
#ifndef WITH_SANITIZER
        dlclose(dll);
#endif
    }

    free(user_name);

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
