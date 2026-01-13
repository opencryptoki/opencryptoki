/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * pkcstok_admin - A tool for administrating tokens, such as creating
 * directories, and changing the owner of a token.
 *
 */

#include "platform.h"
#include <errno.h>

#if defined(_AIX)
    #include <limits.h>
    #include <sys/procfs.h>
    const char *__progname = "pkcstok_admin";
#else
    #include <getopt.h>
    #include <linux/limits.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>

#include "slotmgr.h"

#if defined(_AIX)
#define SHM_PREFIX  "/"
#else
#define SHM_PREFIX  "/dev/shm/"
#endif

#define UNUSED(var)            ((void)(var))

#define pr_verbose(...)                 do {                            \
                                            if (verbose)                \
                                                warnx(__VA_ARGS__);     \
                                        } while (0)

static bool verbose = false;
static bool force = false;

static void print_usage(const char *progname)
{
    printf("\nUsage: %s COMMAND [OPTIONS]\n", progname);

    printf("\n COMMANDS:\n");
    printf("  create                Create a new token and its directories.\n");
    printf("  chown                 Change the owner of the token.\n");
    printf("  remove                Remove a token and its directories.\n"
           "                        This also removes all token objects.\n"
           "                        Use with care!\n");
    printf("  reset                 Reset a token to its initial state. This\n"
           "                        also resets all PINs and removes all token\n"
           "                        objects. Use with care!\n");

    printf("\n OPTIONS:\n");
    printf("  -t, --token TOKNAME   The name of the token to operate on.\n"
           "                        This option is mandatory.\n");
    printf("  -g, --group GROUP     The name of the user group owning the token.\n"
           "                        This option is optional, the default is\n"
           "                        '%s'.\n", PKCS_GROUP);
    printf("  -f, --force           Do not ask for confirmations. Use with care!\n");
    printf("  -h, --help            Print this help, then exit.\n");
    printf("  -v, --version         Print version information, then exit.\n");
    printf("  -V, --verbose         Print verbose messages.\n");

    printf("\n");
}

static void print_version(const char *progname)
{
    printf("%s version %s\n", progname, PACKAGE_VERSION);
}

static bool pkcsslotd_running(void)
{
    FILE *fp;
    char* endptr;
    long lpid;
    char fname[PATH_MAX];
    char buf[PATH_MAX];
#if defined(_AIX)
    struct psinfo psinfo;
#else
    char* first;
#endif

    pr_verbose("Checking if pkcsslotd is running ...");

    fp = fopen(PID_FILE_PATH, "r");
    if (fp == NULL) {
        pr_verbose("Pid file '%s' not existent, pkcsslotd is not running",
                   PID_FILE_PATH);
        return false;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        pr_verbose("Cannot read pid file '%s': %s", PID_FILE_PATH,
                   strerror(errno));
        fclose(fp);
        return false;
    }
    fclose(fp);

    lpid = strtol(buf, &endptr, 10);
    if (*endptr != '\0' && *endptr != '\n') {
        pr_verbose("Failed to parse pid file '%s': %s", PID_FILE_PATH, buf);
        return false;
    }

#if defined(_AIX)
    snprintf(fname, sizeof(fname), "/proc/%ld/psinfo", lpid);
#else
    snprintf(fname, sizeof(fname), "/proc/%ld/cmdline", lpid);
#endif
    fp = fopen(fname, "r");
    if (fp == NULL) {
        pr_verbose("Stale pid file, pkcsslotd is not running");
        return false;
    }

#if defined(_AIX)
    if (fread(&psinfo, sizeof(psinfo), 1, fp) != 1) {
#else
    if (fgets(buf, sizeof(buf), fp) == NULL) {
#endif
        pr_verbose("Failed to read '%s'", fname);
        fclose(fp);
        return false;
    }
    fclose(fp);

#if defined(_AIX)
    return (strstr(psinfo.pr_fname, "pkcsslotd") != NULL);
#else
    first = strtok(buf, " ");
    return (first != NULL && strstr(first, "pkcsslotd") != NULL);
#endif
}

static char prompt_user(const char *message, char* allowed_chars)
{
    int len;
    size_t linelen = 0;
    char *line = NULL;
    char ch = '\0';

    printf("%s", message);

    while (1) {
        len = getline(&line, &linelen, stdin);
        if (len == -1)
            break;

        if (strlen(line) == 2 && strpbrk(line, allowed_chars) != 0) {
            ch = line[0];
            break;
        }

        warnx("Improper reply, try again");
    }

    if (line != NULL)
        free(line);

    return ch;
}

static bool check_group(const char *group, struct group **grp_ret)
{
    struct group grp_buf, *tok_grp, *pkcs11_grp = NULL;
    struct passwd *pwd;
    int i, k, err, found;
    long buf_size;
    char *buff = NULL;
    bool ret = true;

    if (group == NULL)
        group = PKCS_GROUP;

    pr_verbose("Checking group '%s'", group);

    errno = 0;
    tok_grp = getgrnam(group);
    err = (errno != 0 ? errno : ENOENT);
    if (tok_grp == NULL) {
        warnx("Group '%s' does not exist [errno=%s].", group, strerror(err));
        return false;
    }


    if (grp_ret != NULL)
        *grp_ret = tok_grp;

    /* No further check if token group is 'pkcs11' */
    if (strcmp(tok_grp->gr_name, PKCS_GROUP) == 0)
        return true;

    /*
     * Must use getgrnam_r() here, because getgrnam() used above returns a
     * pointer to a static area that would be reused/overwritten by
     * subsequent calls to getgrnam().
     */
    buf_size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buf_size <= 0) {
        err = errno;
        warnx("sysconf(_SC_GETGR_R_SIZE_MAX) failed [errno=%s].",
              strerror(err));
        return false;
    }

retry:
    buff = calloc(1, buf_size);
    if (buff == NULL) {
        warnx("Failed to allocate a buffer of %ld bytes.", buf_size);
        return false;
    }

    errno = 0;
    if (getgrnam_r(PKCS_GROUP, &grp_buf, buff, buf_size, &pkcs11_grp) != 0) {
        err = (errno != 0 ? errno : ENOENT);
        if (err == ERANGE && buf_size < 64 * 1024) {
            free(buff);
            buf_size *= 2;
            goto retry;
        }

        warnx("Group '%s' does not exist [errno=%s].", PKCS_GROUP,
              strerror(err));
        ret = false;
        goto done;
    }

    /* Check that all group members are also a member of the 'pkcs11' group */
    for (i = 0; tok_grp->gr_mem[i] != NULL; i++) {
        pr_verbose("Checking user '%s'", tok_grp->gr_mem[i]);

        /* Check if user's primary group is the 'pkcs11' group */
        errno = 0;
        pwd = getpwnam(tok_grp->gr_mem[i]);
        err = (errno != 0 ? errno : ENOENT);
        if (pwd == NULL) {
            warnx("User '%s' does not exist [errno=%s].\n", tok_grp->gr_mem[i],
                  strerror(err));
            ret = false;
            /* Continue to display all missing users */
            continue;
        }

        if (pwd->pw_gid != pkcs11_grp->gr_gid) {
            /* Check the users secondary groups */
            for (k = 0, found = 0; pkcs11_grp->gr_mem[k] != NULL; k++) {
                if (strcmp(tok_grp->gr_mem[i], pkcs11_grp->gr_mem[k]) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                warnx("User '%s' is member of the token group '%s', but is not a "
                      "member of the '%s' group.", tok_grp->gr_mem[i],
                      tok_grp->gr_name, PKCS_GROUP);
                ret = false;
                /* Continue to display all missing users */
                continue;
            }
        }
    }

done:
    free(buff);

    return ret;
}

static void print_config_example(const char *token, const char *group)
{
    printf("Make sure that the slot definition in '%s'\n"
           "contains the token name '%s'", OCK_CONFIG, token);
    if (group != NULL)
        printf(" and the user group '%s'", group);
    printf(".\n");
    printf("Example:\n");
    printf("    slot <n>\n");
    printf("    {\n");
    printf("      ...\n");
    printf("      tokname = %s\n", token);
    if (group != NULL)
        printf("      usergroup = %s\n", group);
    printf("    }\n\n");
}

static bool check_file_exists(const char *fname, bool directory)
{
    struct stat sb;

    if (stat(fname, &sb) != 0)
        return false;

    if (directory && S_ISDIR(sb.st_mode))
        return true;
    if (!directory && S_ISREG(sb.st_mode))
        return true;

    return false;
}

static int set_file_permissions(const char *fname, const struct group *group,
                                bool recursive)
{
    struct stat sb;
    struct passwd *pwd;
    int err, i, rc, mode;
    bool found = false;
    uid_t uid = (uid_t)-1;
    DIR *dir;
    struct dirent *entry;
    char ent[PATH_MAX];

    pr_verbose("Setting permissions for '%s' with group '%s'", fname,
               group->gr_name);

    /* CWE-59 fix: Use lstat to detect symlinks */
    if (lstat(fname, &sb) != 0) {
        warnx("'%s' does not exist.", fname);
        return -1;
    }

    /* Only process regular files and directories (CWE-59 fix) */
    if (!S_ISREG(sb.st_mode) && !S_ISDIR(sb.st_mode)) {
        warnx("Skipping '%s': not a regular file or directory.", fname);
        return 0;
    }

    if (sb.st_uid != 0) {
        /* owner is not root */
        pwd = getpwuid(sb.st_uid);
        /* If pwd is NULL, found will stay false and root is set as owner */

        for (i = 0; pwd != NULL && group->gr_mem[i] != NULL; i++) {
            if (strcmp(group->gr_mem[i], pwd->pw_name) == 0) {
                found = true;
                break;
            }
        }

        if (!found)
            uid = 0; /* set root as owner if prev owner is not in token group */
    }

    /* Set absolute permissions or rw-rw---- / rwxrwx--- */
    if (S_ISDIR(sb.st_mode))
        mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
    else
        mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    if (chmod(fname, mode) != 0) {
        err = errno;
        warnx("Failed to set permissions on '%s': %s", fname, strerror(err));
        return -1;
    }

    /* Set owner to uid and token group */
    if (chown(fname, uid, group->gr_gid) != 0) {
        err = errno;
        warnx("Failed to change the owner on '%s': %s", fname, strerror(err));
        return -1;
    }

    if (recursive && S_ISDIR(sb.st_mode)) {
        dir = opendir(fname);
        if (dir == NULL) {
            err = errno;
            warnx("Failed to open directory '%s': %s", fname, strerror(err));
            return -1;
        }

        /* set permissions recursively, skip the "." and ".." entries */
        rc = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, ".", 1) == 0)
                continue;

            snprintf(ent, PATH_MAX, "%s/%s", fname, entry->d_name);
            rc = set_file_permissions(ent, group, recursive);
            if (rc != 0)
                break;
        }

        closedir(dir);

        if (rc != 0)
            return rc;
    }

    return 0;
}

static int remove_recursive(const char *fname, bool only_content)
{
    struct stat sb;
    DIR *dir;
    struct dirent *entry;
    int rc, err;
    char ent[PATH_MAX];

    pr_verbose("Removing %s'%s'", only_content ? "the content of " : "", fname);

    if (stat(fname, &sb) != 0) {
        err = errno;
        if (err == ENOENT) {
            /* Removing a non-existing file is a no-op */
            pr_verbose("'%s' does not exists.", fname);
            return 0;
        }

        warnx("Failed to stat '%s': %s.", fname, strerror(err));
        return -1;
    }

    if (S_ISDIR(sb.st_mode)) {
        dir = opendir(fname);
        if (dir == NULL) {
            err = errno;
            warnx("Failed to open directory '%s': %s", fname, strerror(err));
            return -1;
        }

        /* remove directory recursively, skip the "." and ".." entries */
        rc = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, ".", 1) == 0)
                continue;

            snprintf(ent, PATH_MAX, "%s/%s", fname, entry->d_name);
            rc = remove_recursive(ent, false);
            if (rc != 0)
                break;
        }

        closedir(dir);

        if (rc != 0)
            return rc;
    }

    if (!only_content) {
        rc = remove(fname);
        if (rc != 0) {
            err = errno;
            warnx("Failed to remove '%s': %s", fname, strerror(err));
            return -1;
        }
    }

    return 0;
}

static int create_directory(const char *dirname, const struct group *group)
{
    pr_verbose("Creating directory '%s'", dirname);

    if (mkdir(dirname, S_IRWXU | S_IRWXG) != 0) {
        warnx("Failed to create directory '%s': %s", dirname, strerror(errno));
        return -1;
    }

    return set_file_permissions(dirname, group, false);
}

static int get_token_dir(const char *token, char *fpath, size_t fpath_size)
{
    int len;

    len = snprintf(fpath, fpath_size, "%s/%s", CONFIG_PATH, token);
    if (len < 0 || (size_t)len >= fpath_size) {
        pr_verbose("Token directory name too long");
        return -1;
    }

    pr_verbose("Token directory: %s", fpath);
    return 0;
}

static int get_token_object_dir(const char *token, char *fpath,
                                size_t fpath_size)
{
    int len;

    len = snprintf(fpath, fpath_size, "%s/%s/TOK_OBJ", CONFIG_PATH, token);
    if (len < 0 || (size_t)len >= fpath_size) {
        pr_verbose("Token object directory name too long");
        return -1;
    }
    pr_verbose("Token object directory: %s", fpath);
    return 0;
}

static int get_token_lock_dir(const char *token, char *fpath, size_t fpath_size)
{
    int len;

    len = snprintf(fpath, fpath_size, "%s/%s", LOCKDIR_PATH, token);
    if (len < 0 || (size_t)len >= fpath_size) {
        pr_verbose("Token lock directory name too long");
        return -1;
    }

    pr_verbose("Lock directory: %s", fpath);
    return 0;
}

static int get_token_shm_name(const char *token, char *fpath, size_t fpath_size)
{
    char tok_dir[PATH_MAX], *shmname = fpath;
    size_t len;
    bool verbose_save = verbose;
    int i, rc;

    verbose = false;
    rc = get_token_dir(token, tok_dir, sizeof(tok_dir));
    verbose = verbose_save;
    if (rc != 0) {
        pr_verbose("Token directory name too long");
        return rc;
    }

    len = strlen(tok_dir);

    /* Need a starting '/' */
    if (tok_dir[0] != '/')
        len++;

    if (fpath_size < strlen(SHM_PREFIX) + len + 1) {
        pr_verbose("Token SHM name too long");
        return -1;
    }

    i = 0;
    strcpy(shmname, SHM_PREFIX);
    shmname += strlen(SHM_PREFIX);

    if (tok_dir[0] == '/')
        i++;

    for (; tok_dir[i]; i++, shmname++) {
        if (tok_dir[i] == '/')
            *shmname = '.';
        else
            *shmname = tok_dir[i];
    }
    *shmname = '\0';

    pr_verbose("Token SHM name: %s", fpath);
    return 0;
}

static int perform_create(const char *token, const char *group,
                          const struct group *grp)
{
    char tok_dir[PATH_MAX];
    char tok_obj_dir[PATH_MAX];
    char tok_lock_dir[PATH_MAX];
#if !defined(_AIX)
    char tok_shm[PATH_MAX];
#endif
    char *msg = NULL;
    char ch;

    /* get the token directories and files */
    if (get_token_dir(token, tok_dir, sizeof(tok_dir)) != 0 ||
        get_token_object_dir(token, tok_obj_dir, sizeof(tok_obj_dir)) != 0 ||
        get_token_lock_dir(token, tok_lock_dir, sizeof(tok_lock_dir)) != 0 ||
#if defined(_AIX)
        FALSE) {
#else
        get_token_shm_name(token, tok_shm, sizeof(tok_shm)) != 0) {
#endif
        warnx("Failed to build name of token directory. Possibly name is too long.");
        return EXIT_FAILURE;
    }

    /* Check if the token or any artifacts of it exist already */
    if (check_file_exists(tok_dir, true)) {
        warnx("The token directory for token '%s' exists already.", token);
        return EXIT_FAILURE;
    }
    if (check_file_exists(tok_lock_dir, true)) {
        warnx("The lock directory for token '%s' exists already.", token);
        return EXIT_FAILURE;
    }

    /* AIX does not expose POSIX shared memory segments under /dev/shm/ */
#if !defined(_AIX)
    if (check_file_exists(tok_shm, false)) {
        warnx("The shared memory segment for token '%s' exists already.",
              token);
        return EXIT_FAILURE;
    }
#endif

    if (!force) {
        if (asprintf(&msg, "Create the token directories for token '%s' with "
                     "owner group '%s' [y/n]? ", token, grp->gr_name) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return EXIT_FAILURE;
        }
        ch = prompt_user(msg, "yn");
        free(msg);
        if (ch != 'y')
            return EXIT_FAILURE;
    }

    /* Create the token directories */
    if (create_directory(tok_dir, grp) != 0 ||
        create_directory(tok_obj_dir, grp) != 0 ||
        create_directory(tok_lock_dir, grp) != 0) {
        /* Try to remove already created directories, but ignore errors */
        rmdir(tok_obj_dir);
        rmdir(tok_dir);
        rmdir(tok_lock_dir);
        return EXIT_FAILURE;
    }

    printf("Token directories created successfully for token '%s'.\n\n", token);

    print_config_example(token, group);

    return EXIT_SUCCESS;
}

static int perform_chown(const char *token, const char *group,
                         const struct group *grp)
{
    char tok_dir[PATH_MAX];
    char tok_obj_dir[PATH_MAX];
    char tok_lock_dir[PATH_MAX];
    char tok_shm[PATH_MAX];
    char *msg = NULL;
    char ch;

    /* get the token directories and files */
    if (get_token_dir(token, tok_dir, sizeof(tok_dir)) != 0 ||
        get_token_object_dir(token, tok_obj_dir, sizeof(tok_obj_dir)) != 0 ||
        get_token_lock_dir(token, tok_lock_dir, sizeof(tok_lock_dir)) != 0 ||
        get_token_shm_name(token, tok_shm, sizeof(tok_shm)) != 0) {
        warnx("Failed to build name of token directory. Possibly name is too long.");
        return EXIT_FAILURE;
    }

    /* Check if the token or any artifacts of it exist already */
    if (!check_file_exists(tok_dir, true)) {
        warnx("The token directory for token '%s' does not exist.", token);
        return EXIT_FAILURE;
    }
    if (!check_file_exists(tok_lock_dir, true)) {
        warnx("The lock directory for token '%s' does not exist.", token);
        return EXIT_FAILURE;
    }

    if (!force) {
        if (asprintf(&msg, "Change the owner of token '%s' to group '%s' "
                     "[y/n]? ", token, grp->gr_name) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return EXIT_FAILURE;
        }
        ch = prompt_user(msg, "yn");
        free(msg);
        if (ch != 'y')
            return EXIT_FAILURE;
    }

    if (set_file_permissions(tok_dir, grp, true) != 0 ||
        set_file_permissions(tok_lock_dir, grp, true) != 0) {
        return EXIT_FAILURE;
    }

#if defined(_AIX)
    /*
     * AIX does not expose POSIX shared memory segments under /dev/shm/, so
     * its owners can not be changed per file system. Remove (unlink) the
     * shared memory segment instead, the next application using the token will
     * re-create it with the desired owners and permissions.
     */
    if (shm_unlink(tok_shm) != 0 && errno != ENOENT) {
        warnx("Failed to unlink the shared memory segment '%s': %s",
              tok_shm, strerror(errno));
        return EXIT_FAILURE;
    }
#else
    if (check_file_exists(tok_shm, false) &&
        set_file_permissions(tok_shm, grp, false) != 0) {
        return EXIT_FAILURE;
    }
#endif

    printf("Successfully changed the owner of the directories of token '%s'.\n\n",
           token);

    print_config_example(token, group);

    return EXIT_SUCCESS;
}

static int perform_remove(const char *token, const char *group,
                          const struct group *grp)
{
    char tok_dir[PATH_MAX];
    char tok_lock_dir[PATH_MAX];
    char tok_shm[PATH_MAX];
    char *msg = NULL;
    char ch;

    UNUSED(group);
    UNUSED(grp);

    /* get the token directories and files */
    if (get_token_dir(token, tok_dir, sizeof(tok_dir)) != 0 ||
        get_token_lock_dir(token, tok_lock_dir, sizeof(tok_lock_dir)) != 0 ||
        get_token_shm_name(token, tok_shm, sizeof(tok_shm)) != 0) {
        warnx("Failed to build name of token directory. Possibly name is too long.");
        return EXIT_FAILURE;
    }

    /* Check if the token or any artifacts of it exist already */
    if (!check_file_exists(tok_dir, true)) {
        warnx("The token directory for token '%s' does not exist.", token);
        return EXIT_FAILURE;
    }
    if (!check_file_exists(tok_lock_dir, true)) {
        warnx("The lock directory for token '%s' does not exist.", token);
        return EXIT_FAILURE;
    }

    if (!force) {
        if (asprintf(&msg, "Remove the token directories of token '%s' and all "
                    "its objects [y/n]? ", token) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return EXIT_FAILURE;
        }
        ch = prompt_user(msg, "yn");
        free(msg);
        if (ch != 'y')
            return EXIT_FAILURE;
    }

    if (remove_recursive(tok_dir, false) != 0 ||
        remove_recursive(tok_lock_dir, false) != 0)
        return EXIT_FAILURE;

#if defined(_AIX)
    /*
     * AIX does not expose POSIX shared memory segments under /dev/shm/, so
     * it can not be removed per file system. Remove it using the shm_unlink()
     * call instead.
     */
    if (shm_unlink(tok_shm) != 0 && errno != ENOENT) {
        warnx("Failed to unlink the shared memory segment '%s': %s",
              tok_shm, strerror(errno));
        return EXIT_FAILURE;
    }
#else
    if (remove_recursive(tok_shm, false) != 0)
        return EXIT_FAILURE;
#endif

    printf("Successfully removed the directories of token '%s'.\n",
           token);
    printf("Make sure to also remove the corresponding slot definition in "
           "'%s'\n", OCK_CONFIG);

    return EXIT_SUCCESS;
}

static int perform_reset(const char *token, const char *group,
                         const struct group *grp)
{
    char tok_dir[PATH_MAX];
    char tok_obj_dir[PATH_MAX];
    char tok_shm[PATH_MAX];
    char tok_MK_SO[PATH_MAX];
    char tok_MK_USER[PATH_MAX];
    char tok_NVTOK_DAT[PATH_MAX];
    char *msg = NULL;
    char ch;
    int len;

    UNUSED(group);
    UNUSED(grp);

    /* get the token directories and files */
    if (get_token_dir(token, tok_dir, sizeof(tok_dir)) != 0 ||
        get_token_object_dir(token, tok_obj_dir, sizeof(tok_obj_dir)) != 0 ||
        get_token_shm_name(token, tok_shm, sizeof(tok_shm)) != 0) {
        warnx("Failed to build name of token directory. Possibly name is too long.");
        return EXIT_FAILURE;
    }

    len = snprintf(tok_MK_SO, sizeof(tok_MK_SO), "%s/MK_SO", tok_dir);
    if (len < 0 || (size_t)len >= sizeof(tok_MK_SO)) {
        warnx("Failed to build name of token MK_SO. Possibly name is too long.");
        return EXIT_FAILURE;
    }

    len = snprintf(tok_MK_USER, sizeof(tok_MK_USER), "%s/MK_USER", tok_dir);
    if (len < 0 || (size_t)len >= sizeof(tok_MK_USER)) {
        warnx("Failed to build name of token MK_USER. Possibly name is too long.");
        return EXIT_FAILURE;
    }

    len = snprintf(tok_NVTOK_DAT, sizeof(tok_NVTOK_DAT), "%s/NVTOK.DAT",
                   tok_dir);
    if (len < 0 || (size_t)len >= sizeof(tok_NVTOK_DAT)) {
        warnx("Failed to build name of token NVTOK.DAT. Possibly name is too long.");
        return EXIT_FAILURE;
    }

    /* Check if the token or any artifacts of it exist already */
    if (!check_file_exists(tok_dir, true)) {
        warnx("The token directory for token '%s' does not exist.", token);
        return EXIT_FAILURE;
    }

    if (!force) {
        if (asprintf(&msg, "Reset token '%s' and its PINs and remove all its "
                     "objects [y/n]? ", token) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return EXIT_FAILURE;
        }
        ch = prompt_user(msg, "yn");
        free(msg);
        if (ch != 'y')
            return EXIT_FAILURE;
    }

    if (remove_recursive(tok_obj_dir, true) != 0 ||
        remove_recursive(tok_MK_SO, false) != 0 ||
        remove_recursive(tok_MK_USER, false) != 0 ||
        remove_recursive(tok_NVTOK_DAT, false) != 0)
        return EXIT_FAILURE;

#if defined(_AIX)
    /*
     * AIX does not expose POSIX shared memory segments under /dev/shm/, so
     * it can not be removed per file system. Remove it using the shm_unlink()
     * call instead.
     */
    if (shm_unlink(tok_shm) != 0 && errno != ENOENT) {
        warnx("Failed to unlink the shared memory segment '%s': %s",
              tok_shm, strerror(errno));
        return EXIT_FAILURE;
    }
#else
    if (remove_recursive(tok_shm, false) != 0)
        return EXIT_FAILURE;
#endif

    printf("Successfully resetted token '%s'.\n\n", token);

    printf("You must now initialize the token freshly using 'pkcsconf -I, set\n"
           "the SO pin using 'pkcsconf -P' and then initialize the USER pin\n"
           "using 'pkcsconf -u'.\n");

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    int rc, opt = 0;
    const char *command = NULL;
    const char *token = NULL, *group = NULL;
    struct group *tok_grp = NULL;

    static const struct option long_opts[] = {
        {"token", required_argument, NULL, 't'},
        {"group", required_argument, NULL, 'g'},
        {"force", no_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {"verbose", no_argument, NULL, 'V'},
        {0, 0, 0, 0}
    };

    /* Get command (if any) */
    if (argc >= 2 && strncmp(argv[1], "-", 1) != 0) {
        command = argv[1];
        argc--;
        argv = &argv[1];
    }

    while ((opt = getopt_long(argc, argv, ":t:g:hvV", long_opts, NULL)) != -1) {
        switch (opt) {
        case 't':
            token = optarg;
            break;
        case 'g':
            group = optarg;
            break;
        case 'V':
            verbose = true;
            break;
        case 'f':
            force = true;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'v':
            print_version(argv[0]);
            exit(EXIT_SUCCESS);
        case ':':
            warnx("Option '%s' requires an argument", argv[optind - 1]);
            exit(EXIT_FAILURE);
        case '?': /* An invalid option has been specified */
            if (optopt)
                warnx("Invalid option '-%c'", optopt);
            else
                warnx("Invalid option '%s'", argv[optind - 1]);
            exit(EXIT_FAILURE);
        default:
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (command == NULL) {
        warnx("A command is required. Use '-h'/'--help' to see the list of "
              "supported commands");
        rc = EXIT_FAILURE;
        goto out;
    }

    if (token == NULL) {
        warnx("Option '-t/--token' is required but not specified.");
        rc = EXIT_FAILURE;
        goto out;
    }
    if (strcmp(token, "HSM_MK_CHANGE") == 0) {
        warnx("The token name 'HSM_MK_CHANGE' is reserved and can not be used.");
        rc = EXIT_FAILURE;
        goto out;
    }

    /* Ensure we are running as root */
    if (geteuid() != 0) {
        warnx("This utility can only be used as root");
        rc = EXIT_FAILURE;
        goto out;
    }

    /* Check if pkcsslotd is running */
    if (pkcsslotd_running()) {
        warnx("The pkcsslotd must be stopped before running this utility.");
        rc = EXIT_FAILURE;
        goto out;
    }

    pr_verbose("Command: %s", command);
    pr_verbose("Token: %s", token);
    pr_verbose("Group: %s", group != NULL ? group : "[omitted]");

    if (!check_group(group, &tok_grp)) {
        rc = EXIT_FAILURE;
        goto out;
    }

    if (strcasecmp(command, "create") == 0) {
        rc = perform_create(token, group, tok_grp);
    } else if (strcasecmp(command, "chown") == 0) {
        rc = perform_chown(token, group, tok_grp);
    } else if (strcasecmp(command, "remove") == 0) {
        rc = perform_remove(token, group, tok_grp);
    } else if (strcasecmp(command, "reset") == 0) {
        rc = perform_reset(token, group, tok_grp);
    } else {
        warnx("Invalid command '%s'", command);
        rc = EXIT_FAILURE;
        goto out;
    }

out:
    pr_verbose("Finished with rc=%d", rc);

    return rc;
}
