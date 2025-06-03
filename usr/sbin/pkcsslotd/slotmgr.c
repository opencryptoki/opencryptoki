/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <openssl/evp.h>

#include "log.h"
#include "slotmgr.h"
#include "pkcsslotd.h"
#include "cfgparser.h"
#include "configuration.h"

#define OBJ_DIR "TOK_OBJ"
#define MD5_HASH_SIZE 16

#define DEF_MANUFID "IBM"

#if defined(_AIX)
    #define DEF_SLOTDESC    "AIX"
    #include <sys/types.h>
    #include <sys/priv.h>
    #include <sys/procfs.h>
    #include <userpriv.h>
    #include <fcntl.h>
#else
    #include <sys/prctl.h>
    #include <sys/capability.h>
    #define DEF_SLOTDESC    "Linux"
#endif

typedef char md5_hash_entry[MD5_HASH_SIZE];
md5_hash_entry tokname_hash_table[NUMBER_SLOTS_MANAGED];

Slot_Mgr_Shr_t *shmp;           // pointer to the shared memory region.
int shmid;
key_t tok;
Slot_Info_t_64 sinfo[NUMBER_SLOTS_MANAGED];
unsigned int NumberSlotsInDB = 0;
int event_support_disabled = 0;

Slot_Info_t_64 *psinfo;

Slot_Mgr_Socket_t socketData;

struct dircheckinfo_s {
    const char *dir;
    int mode;
    int owner_pkcsslotd;
};

/*
   We make main() able to modify Daemon so that we can
   daemonize or not based on a command-line argument
 */
extern BOOL Daemon;
extern BOOL IveDaemonized;

void DumpSharedMemory(void)
{
    u_int32 *p;
    char buf[4 * 8 + 4];
    u_int32 i;

    p = (u_int32 *) shmp;

    for (i = 0; i < 15; i++) {
        sprintf(buf, "%08X %08X %08X %08X", p[0 + (i * 4)], p[1 + (i * 4)],
                p[2 + (i * 4)], p[3 + (i * 4)]);
        LogLog(buf);
    }
}

int compute_hash(int hash_type, int buf_size, char *buf, char *digest)
{
    EVP_MD_CTX *md_ctx = NULL;
    unsigned int result_size;
    int rc;

    md_ctx = EVP_MD_CTX_create();

    switch (hash_type) {
    case HASH_SHA1:
        rc = EVP_DigestInit(md_ctx, EVP_sha1());
        break;
    case HASH_MD5:
        rc = EVP_DigestInit(md_ctx, EVP_md5());
        break;
    default:
        EVP_MD_CTX_destroy(md_ctx);
        return -1;
        break;
    }

    if (rc != 1) {
        fprintf(stderr, "EVP_DigestInit() failed: rc = %d\n", rc);
        return -1;
    }

    rc = EVP_DigestUpdate(md_ctx, buf, buf_size);
    if (rc != 1) {
        fprintf(stderr, "EVP_DigestUpdate() failed: rc = %d\n", rc);
        return -1;
    }

    result_size = EVP_MD_CTX_size(md_ctx);
    rc = EVP_DigestFinal(md_ctx, (unsigned char *) digest, &result_size);
    if (rc != 1) {
        fprintf(stderr, "EVP_DigestFinal() failed: rc = %d\n", rc);
        return -1;
    }
    EVP_MD_CTX_destroy(md_ctx);
    return 0;
}

#if defined(_AIX)
/*
 * Naming is hard! What's called capabilities on Linux is called privileges
 * on AIX. To make matters worse, user privileges are also called privileges.
 */
int drop_capabilities(void)
{
    privg_t priv_set;

    if (getppriv(-1, PRIV_MAXIMUM, priv_set, sizeof(priv_set)) == -1) {
        fprintf(stderr,
            "Failed to get process privileges: %s\n", strerror(errno));
        return -1;
    }

    priv_clrall(priv_set);
    if (setppriv(-1, priv_set, priv_set, priv_set, priv_set) == -1) {
        fprintf(stderr,
            "Failed to set process privileges: %s\n", strerror(errno));
        return -1;
    }

    DbgLog(DL0, "All privileges sucessfully dropped.\n");
    return 0;
}
#else
/*
 * Drop any effective and permitted capabilities (if any).
 * This function is called after initialization, but before becoming a daemon.
 */
int drop_capabilities(void)
{
    cap_t caps;

    caps = cap_get_proc();
    if (caps == NULL) {
        fprintf(stderr, "Failed to get process capabilities: %s\n",
                strerror(errno));
        return -1;
    }

    if (cap_clear(caps) != 0) {
        fprintf(stderr, "Failed to clear capabilities: %s\n",
                strerror(errno));
        cap_free(caps);
        return -1;
    }

    if (cap_set_proc(caps) != 0) {
        fprintf(stderr, "Failed to set process's capabilities: %s\n",
                strerror(errno));
        cap_free(caps);
        return -1;
    }

    cap_free(caps);

    DbgLog(DL0, "Dropped all capabilities.\n");

    return 0;
}
#endif

/*
 * This function is called only when running as root user.
 * Change uid to 'pkcsslotd' and gid to 'pkcs11' and set the group access list
 * to the groups of user 'pkcsslotd'.
 * The setuid() call also drops all capabilities (effective and permitted).
 * The pkcsslotd is then restarted via execv() which applies the capabilities
 * of the executable file (if any) to the running process, just as if
 * pkcsslotd was started as pkcsslotd user right away.
 */
void drop_privileges(struct passwd *pwd)
{
    char program[PATH_MAX + 1] = { 0, };
    char* args[] = { program, NULL };

#if defined(_AIX)
    struct psinfo ps;
    char procpath[PATH_MAX + 1] = { NULL, };
    int psfd;

    snprintf(procpath, PATH_MAX, "/proc/%lld/psinfo", getpid());
    psfd = open(procpath, O_RDONLY);
    if (psfd == -1) {
        fprintf(stderr,
                "Failed to open procfs to read cmdname: %s\n", strerror(errno));
        exit(1);
    }

    if (read(psfd, &ps, sizeof(ps)) == -1) {
        fprintf(stderr, "Failed to populate psinfo: %s\n", strerror(errno));
        exit(1);
    }
    close(psfd);
    /*
     * Copies only argv[0], as maintained by the kernel. This is because
     * parameters are guaranteed to be separated by NULL, which is where strcpy
     * stops copying.
     */
    strncpy(program, ps.pr_psargs, PATH_MAX);

#else
    if (readlink("/proc/self/exe", program, PATH_MAX) == -1) {
        fprintf(stderr, "Failed to get executable file name: %s\n",
                strerror(errno));
        exit(1);
    }
#endif

    if (initgroups(pwd->pw_name, pwd->pw_gid) != 0) {
        fprintf(stderr, "Failed to set the group access list: %s\n",
                strerror(errno));
        exit(1);
    }

    if (setgid(pwd->pw_gid) != 0) {
        fprintf(stderr, "Failed to set gid to '%s': %s\n", PKCS_GROUP,
                strerror(errno));
        exit(1);
    }

    if (setuid(pwd->pw_uid) != 0) {
        fprintf(stderr, "Failed to set uid to '%s': %s\n", PKCSSLOTD_USER,
                strerror(errno));
        exit(1);
    }

    DbgLog(DL0, "Changed uid from 'root' to '%s' and gid to '%s'.\n",
           PKCSSLOTD_USER, PKCS_GROUP);

    /*
     * Start pkcsslotd again as pkcsslotd user. This will also apply the
     * capabilities to those that are set for the executable file (if any).
     */
    if (execv(program, args) != 0) {
        fprintf(stderr, "Failed to re-start pkcsslotd: %s\n",
                strerror(errno));
        exit(1);
    }
}

/** This function does basic sanity checks to make sure the
 *  eco system is in place for opencryptoki to run properly.
 **/
void run_sanity_checks(void)
{
    int i, ec;
    uid_t uid;
    gid_t gid;
    struct passwd *pwd;
    struct group *grp;
    struct stat sbuf;
    struct dircheckinfo_s dircheck[] = {
        { RUN_DIR, S_IRWXU | S_IXGRP, 1 },
        { LOCKDIR_PATH, S_IRWXU | S_IRWXG, 0 },
        { OCK_LOGDIR, S_IRWXU | S_IRWXG, 0 },
        { CONFIG_PATH, S_IRWXU | S_IRWXG, 0 },
        { OCK_HSM_MK_CHANGE_PATH, S_IRWXU | S_IRWXG, 0 },
        { NULL, 0, 0 },
    };

    /* check that the pkcsslotd user exists */
    pwd = getpwnam(PKCSSLOTD_USER);
    if (pwd == NULL) {
        fprintf(stderr, "There is no '%s' user on this system.\n",
                PKCSSLOTD_USER);
        exit(1);
    }

    /* check that the pkcs11 group exists */
    grp = getgrnam(PKCS_GROUP);
    if (!grp) {
        fprintf(stderr, "There is no '%s' group on this system.\n", PKCS_GROUP);
        exit(1);
    }

    /* check that our effective user id is pkcsslotd or root */
    uid = geteuid();
    if (uid != 0 && uid != pwd->pw_uid) {
        fprintf(stderr, "This daemon needs to be run under the '%s' "
                "or the 'root' user.\n", PKCSSLOTD_USER);
        exit(1);
    }

    /* check effective group id */
    gid = getegid();
    if (gid != 0 && gid != grp->gr_gid) {
        fprintf(stderr, "This daemon should have an effective group id of "
                "'root' or '%s'.\n", PKCS_GROUP);
        exit(1);
    }

    /*
     * Check if base directories exist. If not, create them.
     * Creation of the directory will only work if running as root.
     * The directories are usually created by tmpfiles.d during system startup.
     */
    for (i = 0; dircheck[i].dir != NULL; i++) {
        ec = stat(dircheck[i].dir, &sbuf);
        if (ec != 0 && errno == ENOENT) {
            /* dir does not exist, try to create it */
            ec = mkdir(dircheck[i].dir, dircheck[i].mode);
            if (ec != 0) {
                fprintf(stderr, "Directory %s missing\n", dircheck[i].dir);
                exit(2);
            }
            /* set ownership to root or pkcsslotd, and pkcs11 group */
            if (chown(dircheck[i].dir,
                      dircheck[i].owner_pkcsslotd ? pwd->pw_uid : geteuid(),
                      grp->gr_gid) != 0) {
                fprintf(stderr,
                        "Failed to set owner:group ownership on %s directory\n",
                        dircheck[i].dir);
                exit(1);
            }
            /* mkdir does not set group permission right, so
             * trying explictly here again */
            if (chmod(dircheck[i].dir, dircheck[i].mode) != 0) {
                fprintf(stderr,
                        "Failed to change permissions on %s directory\n",
                        dircheck[i].dir);
                exit(1);
            }
        }
    }

    if (uid == 0)
        drop_privileges(pwd);

/* AIX setppriv handles this already */
#if !defined(_AIX)
    /* Do not allow execve() to grant additional privileges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "Failed to set NO_NEW_PRIVS flag: %s\n",
                strerror(errno));
        exit(1);
    }
#endif
    if (chdir(RUN_DIR) != 0) {
        fprintf(stderr, "Failed to set current directory: %s\n",
                strerror(errno));
        exit(1);
    }
}

int is_duplicate(md5_hash_entry hash, md5_hash_entry *hash_table)
{
    int i;

    for (i = 0; i < NUMBER_SLOTS_MANAGED; i++) {
        if (memcmp(hash_table[i], hash, sizeof(md5_hash_entry)) == 0)
            return 1;
    }

    return 0;
}

int check_token_group(struct group *tok_grp)
{
    struct group grp_buf, *pkcs11_grp = NULL;
    struct passwd *pwd;
    int i, k, err, found, rc = 0;
    long buf_size;
    char *buff = NULL;

    /* No further check if token group is 'pkcs11' */
    if (strcmp(tok_grp->gr_name, PKCS_GROUP) == 0)
        return 0;

    /*
     * Must use getgrnam_r() here, because caller is using getgrnam() which
     * returns a pointer to a static area that would be reused/overwritten by
     * subsequent calls to getgrnam().
     */
    buf_size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buf_size <= 0) {
        err = errno;
        fprintf(stderr, "sysconf(_SC_GETGR_R_SIZE_MAX) failed [errno=%s].\n",
                strerror(err));
        return err;
    }

retry:
    buff = calloc(1, buf_size);
    if (buff == NULL) {
        fprintf(stderr, "Failed to allocate a buffer of %ld bytes.\n",
                buf_size);
        return ENOMEM;
    }

    errno = 0;
    if (getgrnam_r(PKCS_GROUP, &grp_buf, buff, buf_size, &pkcs11_grp) != 0) {
        err = (errno != 0 ? errno : ENOENT);
        if (err == ERANGE && buf_size < 64 * 1024) {
            free(buff);
            buf_size *= 2;
            goto retry;
        }

        fprintf(stderr, "Group '%s' does not exist [errno=%s].\n", PKCS_GROUP,
                strerror(err));
       rc = err;
       goto done;
    }

    /* Check that all group members are also a member of the 'pkcs11' group */
    for (i = 0; tok_grp->gr_mem[i] != NULL; i++) {
        /* Check if user's primary group is the 'pkcs11' group */
        errno = 0;
        pwd = getpwnam(tok_grp->gr_mem[i]);
        err = (errno != 0 ? errno : ENOENT);
        if (pwd == NULL) {
            fprintf(stderr, "USer '%s' does not exist [errno=%s].\n",
                    tok_grp->gr_mem[i], strerror(err));
            rc = EINVAL;
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
                fprintf(stderr, "User '%s' is member of the token group '%s', "
                        "but is not a member of the '%s' group.\n",
                        tok_grp->gr_mem[i], tok_grp->gr_name, PKCS_GROUP);
                rc = EINVAL;
                /* Continue to display all missing users */
                continue;
            }
        }
    }

done:
    free(buff);
    return rc;
}

int chk_create_tokdir(Slot_Info_t_64 *psinfo)
{
    struct stat sbuf;
    char tokendir[PATH_MAX];
    struct group *grp;
    gid_t grpid;
    int uid, rc, err;
    mode_t proc_umask;
    char *tokdir = psinfo->tokname;
    char *tokgroup = psinfo->usergroup;
    char token_md5_hash[MD5_HASH_SIZE];

    if (psinfo->present == FALSE)
        return 0;

    proc_umask = umask(0);

    if (strlen(tokgroup) == 0)
        tokgroup = PKCS_GROUP;

    /* get token group id */
    uid = (int) geteuid();
    errno = 0;
    grp = getgrnam(tokgroup);
    err = (errno != 0 ? errno : ENOENT);
    if (!grp) {
        fprintf(stderr, "Token group '%s' does not exist [errno=%s].\n",
                tokgroup, strerror(err));
        return err;
    } else {
        grpid = grp->gr_gid;
    }

    rc = check_token_group(grp);
    if (rc)
        return rc;

    /*
     * Skip if no dedicated token directory is required. If no 'tokname' is
     * specified, the token directory name is not known, thus we can not check
     * or create it.
     */
    if (!tokdir || strlen(tokdir) == 0) {
        /*
         * Build the md5 hash from the dll name prefixed with 'dll:' to
         * check for duplicate tokens with no 'tokname'.
         */
        snprintf(tokendir, sizeof(tokendir), "dll:%s", psinfo->dll_location);
        rc = compute_md5(tokendir, strlen(tokendir), token_md5_hash);
        if (rc) {
            fprintf(stderr, "Error calculating MD5 of token name!\n");
            return -1;
        }

        /* check for duplicate token names */
        if (is_duplicate(token_md5_hash, tokname_hash_table)) {
            fprintf(stderr, "Duplicate token in slot %llu!\n",
                    psinfo->slot_number);
            return -1;
        }

        /* add entry into hash table */
        memcpy(tokname_hash_table[psinfo->slot_number], token_md5_hash,
               MD5_HASH_SIZE);

        return 0;
    }

    /* Check if the path length fits in the max path length
       (include 2 * / and 0)
     */
    if (strlen(CONFIG_PATH) + strlen(tokdir) + strlen(OBJ_DIR) + 3 > PATH_MAX) {
        fprintf(stderr, "Path name for token object directory too long!\n");
        return -1;
    }

    /* calculate md5 hash from token name */
    rc = compute_md5(tokdir, strlen(tokdir), token_md5_hash);
    if (rc) {
        fprintf(stderr, "Error calculating MD5 of token name!\n");
        return -1;
    }
    /* check for duplicate token names */
    if (is_duplicate(token_md5_hash, tokname_hash_table)) {
        fprintf(stderr, "Duplicate token name '%s'!\n", tokdir);
        return -1;
    }

    /* add entry into hash table */
    memcpy(tokname_hash_table[psinfo->slot_number], token_md5_hash,
           MD5_HASH_SIZE);

    /* Create token specific directory */
    /* sprintf checked above */
    sprintf(tokendir, "%s/%s", CONFIG_PATH, tokdir);
    rc = stat(tokendir, &sbuf);
    err = errno;
    if (rc != 0 && err == ENOENT) {
        if (strcmp(tokgroup, PKCS_GROUP) != 0) {
            fprintf(stderr,
                    "Can not create token directory '%s' with a token group "
                    "other than '%s'. You must create the token directory "
                    "using the pkcstok_admin tool with the proper owner "
                    "group.\n", tokendir, PKCS_GROUP);
            umask(proc_umask);
            return EACCES;
        }

        /* directory does not exist, create it */
        rc = mkdir(tokendir, S_IRWXU | S_IRWXG);
        if (rc != 0) {
            fprintf(stderr,
                    "Creating directory '%s' failed [errno=%s].\n",
                    tokendir, strerror(errno));
            umask(proc_umask);
            return rc;
        }

        rc = chown(tokendir, uid, grpid);
        if (rc != 0) {
            fprintf(stderr,
                    "Could not set '%s' group permission [errno=%s].\n",
                    PKCS_GROUP, strerror(errno));
            umask(proc_umask);
            return rc;
        }

    } else if (rc != 0) {
        fprintf(stderr,
                "Could not stat directory '%s' [errno=%s].\n", tokendir,
                strerror(err));
        umask(proc_umask);
        return err;
    } else if (sbuf.st_gid != grpid) {
        fprintf(stderr,
                "Directory '%s' is not owned by token group '%s'.\n",
                tokendir, tokgroup);
        umask(proc_umask);
        return EACCES;
    }

    /*
     * Can not check or create TOK_OBJ directory inside the token directory
     * if the token group is different than 'pkcs11', because the 'pkcsslotd'
     * user does not have permissions to access such a token directory.
     */
    if (strcmp(tokgroup, PKCS_GROUP) != 0) {
        umask(proc_umask);
        return 0;
    }

    /* Create TOK_OBJ directory */
    /* sprintf checked above */
    sprintf(tokendir, "%s/%s/%s", CONFIG_PATH, tokdir, OBJ_DIR);
    rc = stat(tokendir, &sbuf);
    err = errno;
    if (rc != 0 && err == ENOENT) {
        /* directory does not exist, create it */
        rc = mkdir(tokendir, S_IRWXU | S_IRWXG);
        if (rc != 0) {
            fprintf(stderr,
                    "Creating directory '%s' failed [errno=%s].\n",
                    tokendir, strerror(errno));
            umask(proc_umask);
            return rc;
        }

        rc = chown(tokendir, uid, grpid);
        if (rc != 0) {
            fprintf(stderr,
                    "Could not set '%s' group permission [errno=%s].\n",
                    PKCS_GROUP, strerror(errno));
            umask(proc_umask);
            return rc;
        }
    } else if (rc != 0) {
        fprintf(stderr,
                "Could not stat directory '%s' [errno=%s].\n", tokendir,
                strerror(err));
        umask(proc_umask);
        return err;
    } else if (sbuf.st_gid != grpid) {
        fprintf(stderr,
                "Directory '%s' is not owned by token group '%s'.\n",
                tokendir, tokgroup);
        umask(proc_umask);
        return EACCES;
    }
    umask(proc_umask);
    return 0;
}

static int create_pid_file(pid_t pid)
{
    FILE *pidfile;

    pidfile = fopen(PID_FILE_PATH, "w");
    if (!pidfile) {
        fprintf(stderr, "Could not create pid file '%s' [errno=%s].\n",
                PID_FILE_PATH, strerror(errno));
        return -1;
    }

    fprintf(pidfile, "%d\n", (int) pid);
    fflush(pidfile);
    fclose(pidfile);
    InfoLog("PID file (" PID_FILE_PATH ") created");

    return 0;
}

static void config_parse_error(int line, int col, const char *msg)
{
    ErrLog("Error parsing config file: line %d column %d: %s\n", line, col,
           msg);
}

static int do_str(char *slotinfo, size_t size, const char* file,
                  const char* tok, const char *val, char padding)
{
    if (strlen(val) > size) {
        ErrLog("Error parsing config file '%s': %s has too many characters\n",
               file, tok);
        return -1;
    }
    memset(slotinfo, padding, size);
    memcpy(slotinfo, val, strlen(val));
    return 0;
}

static int config_parse_slot(const char *config_file,
                             struct ConfigIdxStructNode *slot)
{
    struct ConfigBaseNode *c;
    int i, slot_no;
    unsigned int vers;
#if defined(_AIX)
    char libname[1025] = {0, };
    char toktype[5] = {0, };
    char *substr = NULL;
    int idx = 0;
#endif
    char *str = NULL;

    slot_no = slot->idx;
    DbgLog(DL3, "Slot: %d\n", slot_no);

    if (slot_no >= NUMBER_SLOTS_MANAGED) {
        ErrLog("Error parsing config file '%s': Slot number %d unsupported! "
               "Slot number has to be less than %d!", config_file, slot_no,
               NUMBER_SLOTS_MANAGED);
        return 1;
    }

    memset(&sinfo[slot_no].slot_number, 0, sizeof(sinfo[slot_no].slot_number));
    sinfo[slot_no].slot_number = slot_no;

    confignode_foreach(c, slot->value, i) {
        DbgLog(DL3, "Config node: '%s' type: %u line: %u\n",
               c->key, c->type, c->line);

        if (strcmp(c->key, "stdll") == 0 &&
            (str = confignode_getstr(c)) != NULL) {
#if defined(_AIX)
           /*
            * AIX bundles libraries as ranlib archives. The objects therefore
            * need to be loaded from within the library. Instead of modifying
            * the parser to handle the new string format, it's easier to just
            * build the string ourselves - this only happens at daemon init,
            * so performance isn't a concern here.
            */
            substr = strrchr(str, '_');
            if (substr == NULL) /* no '_', libname is malformed */
                return 1;

            ++substr;
            while (*substr != '.' && idx < sizeof(toktype) - 1) {
                toktype[idx++] = (char)*substr;
                ++substr;
            }
            snprintf(libname, sizeof(libname),
                    "libpkcs11_%s.a(libpkcs11_%s.so.0)", toktype, toktype);
            str = (char*)libname;
#endif
            if (do_str((char *)&sinfo[slot_no].dll_location,
                       sizeof(sinfo[slot_no].dll_location),
                       config_file, c->key, str, 0))
                return 1;

            sinfo[slot_no].present = TRUE;
            continue;
        }

        if (strcmp(c->key, "description") == 0 &&
            (str = confignode_getstr(c)) != NULL) {
            if (do_str((char *)&sinfo[slot_no].pk_slot.slotDescription,
                       sizeof(sinfo[slot_no].pk_slot.slotDescription),
                       config_file, c->key, str, ' '))
                return 1;

            continue;
        }

        if (strcmp(c->key, "manufacturer") == 0 &&
            (str = confignode_getstr(c)) != NULL) {
            if (do_str((char *)&sinfo[slot_no].pk_slot.manufacturerID,
                       sizeof(sinfo[slot_no].pk_slot.manufacturerID),
                       config_file, c->key, str, ' '))
                return 1;

            continue;
        }

        if (strcmp(c->key, "confname") == 0 &&
            (str = confignode_getstr(c)) != NULL) {
            if (do_str((char *)&sinfo[slot_no].confname,
                       sizeof(sinfo[slot_no].confname),
                       config_file, c->key, str, 0))
                return 1;

            continue;
        }

        if (strcmp(c->key, "tokname") == 0 &&
            (str = confignode_getstr(c)) != NULL) {
            if (do_str((char *)&sinfo[slot_no].tokname,
                       sizeof(sinfo[slot_no].tokname),
                       config_file, c->key, str, 0))
                return 1;

            continue;
        }

        if (strcmp(c->key, "hwversion") == 0 &&
            confignode_getversion(c, &vers) == 0) {
            sinfo[slot_no].pk_slot.hardwareVersion.major = vers >> 16;
            sinfo[slot_no].pk_slot.hardwareVersion.minor = vers & 0xffffu;
            continue;
        }

        if (strcmp(c->key, "firmwareversion") == 0 &&
            confignode_getversion(c, &vers) == 0) {
            sinfo[slot_no].pk_slot.firmwareVersion.major = vers >> 16;
            sinfo[slot_no].pk_slot.firmwareVersion.minor = vers & 0xffffu;
            continue;
        }

        if (strcmp(c->key, "tokversion") == 0 &&
            confignode_getversion(c, &sinfo[slot_no].version) == 0)
            continue;

        if (strcmp(c->key, "usergroup") == 0 &&
            (str = confignode_getstr(c)) != NULL) {
            if (do_str((char *)&sinfo[slot_no].usergroup,
                       sizeof(sinfo[slot_no].usergroup),
                       config_file, c->key, str, 0))
                return 1;

            continue;
        }

        ErrLog("Error parsing config file '%s': unexpected token '%s' "
               "at line %d: \n", config_file, c->key, c->line);
        return 1;
    }

    /* set some defaults if user hasn't set these. */
    if (!sinfo[slot_no].pk_slot.slotDescription[0]) {
        memset(&sinfo[slot_no].pk_slot.slotDescription[0], ' ',
               sizeof(sinfo[slot_no].pk_slot.slotDescription));
        memcpy(&sinfo[slot_no].pk_slot.slotDescription[0],
               DEF_SLOTDESC, strlen(DEF_SLOTDESC));
    }
    if (!sinfo[slot_no].pk_slot.manufacturerID[0]) {
        memset(&sinfo[slot_no].pk_slot.manufacturerID[0], ' ',
               sizeof(sinfo[slot_no].pk_slot.manufacturerID));
        memcpy(&sinfo[slot_no].pk_slot.manufacturerID[0],
               DEF_MANUFID, strlen(DEF_MANUFID));
    }

    NumberSlotsInDB++;

    return 0;
}

static int config_parse_statistics(const char *config_file,
                                   struct ConfigBareListNode *statistics)
{
    struct ConfigBaseNode *c;
    int i;

    confignode_foreach(c, statistics->value, i) {
        DbgLog(DL3, "Config node: '%s' type: %u line: %u\n",
               c->key, c->type, c->line);

        if (c->type == CT_BARE && strcmp(c->key, "off") == 0) {
            socketData.flags &= ~(FLAG_STATISTICS_ENABLED |
                                  FLAG_STATISTICS_IMPLICIT |
                                  FLAG_STATISTICS_INTERNAL);
            continue;
        }
        if (c->type == CT_BARE && strcmp(c->key, "on") == 0) {
            socketData.flags |= FLAG_STATISTICS_ENABLED;
            continue;
        }
        if (c->type == CT_BARE && strcmp(c->key, "implicit") == 0) {
            socketData.flags |= FLAG_STATISTICS_IMPLICIT;
            continue;
        }
        if (c->type == CT_BARE && strcmp(c->key, "internal") == 0) {
            socketData.flags |= FLAG_STATISTICS_INTERNAL;
            continue;
        }

        ErrLog("Error parsing config file '%s': unexpected token '%s' "
               "at line %d: \n", config_file, c->key, c->line);
        return 1;
    }

    return 0;
}

static int config_parse(const char *config_file)
{
    FILE *file;
    struct stat statbuf;
    struct ConfigBaseNode *c, *config = NULL;
    struct ConfigIdxStructNode *slot;
    struct ConfigBareListNode *statistics;
    int i, ret = 0;

    file = fopen(config_file, "r");
    if (file == NULL) {
        ErrLog("Error opening config file '%s': %s\n", config_file,
               strerror(errno));
        return -1;
    }

    if (fstat(fileno(file), &statbuf)) {
        ErrLog("Error get file information for config file '%s': %s\n",
               config_file,
               strerror(errno));
        fclose(file);
        return -1;
    }

    if ((statbuf.st_mode & S_IWOTH)) {
        ErrLog("Config file %s is world writable, this is not accepted\n",
               config_file);
        fclose(file);
         return -1;
    }

    ret = parse_configlib_file(file, &config, config_parse_error, 0);
    fclose(file);
    if (ret != 0) {
        ErrLog("Error parsing config file '%s'\n", config_file);
        goto done;
    }

    confignode_foreach(c, config, i) {
        DbgLog(DL3, "Config node: '%s' type: %u line: %u\n",
               c->key, c->type, c->line);

        if (confignode_hastype(c, CT_FILEVERSION)) {
            DbgLog(DL0, "Config file version: '%s'\n",
                   confignode_to_fileversion(c)->base.key);
            continue;
        }

        if (confignode_hastype(c, CT_BARECONST)) {
            if (strcmp(confignode_to_bareconst(c)->base.key,
                       "disable-event-support") == 0) {
                event_support_disabled = 1;
                continue;
            }

            ErrLog("Error parsing config file '%s': unexpected token '%s' "
                   "at line %d: \n", config_file, c->key, c->line);
            ret = -1;
            break;
        }

        if (confignode_hastype(c, CT_BARELIST)) {
            statistics = confignode_to_barelist(c);
            if (strcmp(statistics->base.key, "statistics") == 0) {
                ret = config_parse_statistics(config_file, statistics);
                if (ret != 0)
                    break;
                continue;
            }

            ErrLog("Error parsing config file '%s': unexpected token '%s' "
                   "at line %d: \n", config_file, c->key, c->line);
            ret = -1;
            break;
        }

        if (confignode_hastype(c, CT_IDX_STRUCT)) {
            slot = confignode_to_idxstruct(c);
            if (strcmp(slot->base.key, "slot") == 0) {
                ret = config_parse_slot(config_file, slot);
                if (ret != 0)
                    break;
                continue;
            }

            ErrLog("Error parsing config file '%s': unexpected token '%s' "
                   "at line %d: \n", config_file, c->key, c->line);
            ret = -1;
            break;
        }

        ErrLog("Error parsing config file '%s': unexpected token '%s' "
               "at line %d: \n", config_file, c->key, c->line);
        ret = -1;
        break;
    }

done:
    confignode_deepfree(config);
    return ret;
}

static int teardown(int rc)
{
    term_socket_server();
    DestroyMutexes();
    DetachFromSharedMemory();
    DestroySharedMemory();
    return rc;
}

static int setup_sock_data(void)
{
    if (!init_socket_data(&socketData)) {
        DestroyMutexes();
        DetachFromSharedMemory();
        DestroySharedMemory();
        return 6;
    }

    if (event_support_disabled)
        socketData.flags |= FLAG_EVENT_SUPPORT_DISABLED;

    /* Create customized token directories */
    psinfo = &socketData.slot_info[0];
    for (int i = 0; i < NUMBER_SLOTS_MANAGED; i++, psinfo++) {
        if (chk_create_tokdir(psinfo)) {
            DestroyMutexes();
            DetachFromSharedMemory();
            DestroySharedMemory();
            return EACCES;
        }
    }
    /* setup completed successfully */
    return 0;
}

static int setup_sock_server(void)
{
    if (!init_socket_server(event_support_disabled)) {
        DestroyMutexes();
        DetachFromSharedMemory();
        DestroySharedMemory();
        return 5;
    }
    /* setup completed successfully */
    return 0;
}

/*****************************************
 *  main() -
 *      You know what main does.
 *      Comment block for ease of spotting
 *      it when paging through file
 *
 *****************************************/

int main(int argc, char *argv[], char *envp[])
{
    int ret;

    /**********************************/
    /* Read in command-line arguments */
    /**********************************/

    /* FIXME: Argument for daemonizing or not */
    /* FIXME: Argument for debug level */
    /* FIXME: Arguments affecting the log files, whether to use syslog, etc.
     * (Read conf file?) */

    UNUSED(argc);
    UNUSED(argv);
    UNUSED(envp);

    /* Do some basic sanity checks */
    run_sanity_checks();

    /* Report our debug level */
    if (GetDebugLevel() > DEBUG_NONE) {
        DbgLog(GetDebugLevel(),
               "Starting with debugging messages logged at level %d "
               "(%d = No messages; %d = few; %d = more, etc.)",
               GetDebugLevel(), DEBUG_NONE, DEBUG_LEVEL0, DEBUG_LEVEL1);
    }

    socketData.flags |= FLAG_STATISTICS_ENABLED;
    ret = config_parse(OCK_CONFIG);
    if (ret != 0) {
        ErrLog("Failed to read config file.\n");
        return 1;
    } else {
        DbgLog(DL0, "Parse config file succeeded.\n");
    }

    /* Allocate and Attach the shared memory region */
    if (!CreateSharedMemory()) {
        /* CreateSharedMemory() does it's own error logging */
        return 1;
    }

    DbgLog(DL0, "SHMID %d  token %#X \n", shmid, tok);

    /* Now that we've created the shared memory segment, we attach to it */
    if (!AttachToSharedMemory()) {
        /* AttachToSharedMemory() does it's own error logging */
        DestroySharedMemory();
        return 2;
    }

    /* Initialize the global shared memory mutex (and the attribute
     * used to create the per-process mutexes */
    if (!InitializeMutexes()) {
        DetachFromSharedMemory();
        DestroySharedMemory();
        return 3;
    }

    /* Get the global shared memory mutex */
    if (!XProcLock())
        return 4;

    /* Populate the Shared Memory Region */
    if (!InitSharedMemory(shmp)) {
        XProcUnLock();

        DetachFromSharedMemory();
        DestroySharedMemory();
        return 4;
    }

    /* Release the global shared memory mutex */
    if (!XProcUnLock())
        return 4;

    if ((ret = setup_sock_data()) != 0)
        return ret;

#if !defined(_AIX)
    if ((ret = setup_sock_server()) != 0)
        return ret;
#endif

    if (drop_capabilities() != 0)
        return 7;

    /*
     *  Become a Daemon, if called for
     */
    if (Daemon) {
        pid_t pid;
        if ((pid = fork()) < 0) {
#if !defined(_AIX)
            term_socket_server();
#endif
            DestroyMutexes();
            DetachFromSharedMemory();
            DestroySharedMemory();
            return 7;
        } else if (pid != 0) {
            /*
             * This is the parent
             * Create the pid file for the client as systemd wants to
             * see the pid file a soon as the parent terminates.
             */
            create_pid_file(pid);
            /* now terminate the parent */
            exit(0);
        } else {
            /* This is the child */
            setsid();       // Session leader
#ifndef DEV
            fclose(stderr);
            fclose(stdout);
            fclose(stdin);
#endif
        }
    } else {
#ifdef DEV
        // Log only on development builds
        LogLog("Not becoming a daemon...\n");
#endif
    }

#if defined(_AIX)
    /*
     * Set up the socket server /after/ the fork on AIX. This is because
     * AIX closes the pollset fd before the fork, with no way of continuing
     * to use it in the child. Therefore, pollset needs to be initialised
     * ONLY in the client process to actually be useful.
     * Quoting from the manpage:
     * A process can call fork after calling pollset_create. The child process
     * will already have a pollset ID per pollset, but pollset_destroy,
     * pollset_ctl, pollset_query, and pollset_poll operations will fail with
     * an errno value of EACCES.
     */
    if ((ret = setup_sock_server()) != 0)
        return ret;
#endif

    /*****************************************
     *
     * Register Signal Handlers
     * Daemon probably should ignore ALL signals possible, since termination
     * while active is a bad thing...  however one could check for
     * any processes active in the shared memory, and destroy the shm if
     * the process wishes to terminate.
     *
     *****************************************/

    /*
     * We have to set up the signal handlers after we daemonize because
     * the daemonization process redefines our handler for (at least) SIGTERM
     */
    if (!SetupSignalHandlers())
        return teardown(8);

    /* ultimately we will create a couple of threads which monitor the slot db
     * and handle the insertion and removal of tokens from the slot.
     */

    /* For Testing the Garbage collection routines */
    /*
     * shmp->proc_table[3].inuse = TRUE;
     * shmp->proc_table[3].proc_id = 24328;
     */

#if !defined(NOGARBAGE)
    /* start garbage collection thread */
    if (!StartGCThread(shmp))
        return teardown(9);
#endif

    /*
     * We've fully become a daemon.
     * In not-daemon mode the pid file hasn't been created jet,
     * so let's do this now.
     */
    if (!Daemon)
        create_pid_file(getpid());

    while (1) {
#if !(THREADED) && !(NOGARBAGE)
        CheckForGarbage(shmp);
#endif
        socket_connection_handler(10);
    }

    /*************************************************************
     *
     * Here we need to actually go through the processes and verify that they
     * still exist.  If not, then they terminated with out properly calling
     * C_Finalize and therefore need to be removed from the system.
     * Look for a system routine to determine if the shared memory is held by
     * the process to further verify that the proper processes are in the
     * table.
     *
     **************************************************************/
}                               /* end main */
