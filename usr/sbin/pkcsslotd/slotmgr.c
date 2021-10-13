/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <string.h>
#include <openssl/evp.h>

#include "log.h"
#include "slotmgr.h"
#include "pkcsslotd.h"
#include "parser.h"

#define OBJ_DIR "TOK_OBJ"
#define MD5_HASH_SIZE 16

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
};

struct parse_data {
    Slot_Info_t_64    sinfo_struct;
    unsigned long int index;
    char              errbuf[256];
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

/** This function does basic sanity checks to make sure the
 *  eco system is in place for opencryptoki to run properly.
 **/
void run_sanity_checks()
{
    int i, ec, uid = -1;
    struct group *grp = NULL;
    struct stat sbuf;
    struct dircheckinfo_s dircheck[] = {
        //drwxrwx---
        {LOCKDIR_PATH, S_IRWXU | S_IRWXG},
        {OCK_LOGDIR, S_IRWXU | S_IRWXG},
        {NULL, 0},
    };

    /* first check that our effective user id is root */
    uid = (int) geteuid();
    if (uid != 0) {
        fprintf(stderr, "This daemon needs root privilegies, "
                "but the effective user id is not 'root'.\n");
        exit(1);
    }

    /* check that the pkcs11 group exists */
    grp = getgrnam("pkcs11");
    if (!grp) {
        fprintf(stderr, "There is no 'pkcs11' group on this system.\n");
        exit(1);
    }

    /* check effective group id */
    uid = (int) getegid();
    if (uid != 0 && uid != (int) grp->gr_gid) {
        fprintf(stderr, "This daemon should have an effective group id of "
                "'root' or 'pkcs11'.\n");
        exit(1);
    }

    /* Create base lock and log directory here. API..Lock file is
     * accessed from the daemon in CreateXProcLock() in mutex.c.*/
    for (i = 0; dircheck[i].dir != NULL; i++) {
        ec = stat(dircheck[i].dir, &sbuf);
        if (ec != 0 && errno == ENOENT) {
            /* dir does not exist, try to create it */
            ec = mkdir(dircheck[i].dir, dircheck[i].mode);
            if (ec != 0) {
                fprintf(stderr, "Directory %s missing\n", dircheck[i].dir);
                exit(2);
            }
            /* set ownership to root, and pkcs11 group */
            if (chown(dircheck[i].dir, geteuid(), grp->gr_gid) != 0) {
                fprintf(stderr,
                        "Failed to set owner:group ownership on %s directory",
                        dircheck[i].dir);
                exit(1);
            }
            /* mkdir does not set group permission right, so
             * trying explictly here again */
            if (chmod(dircheck[i].dir, dircheck[i].mode) != 0) {
                fprintf(stderr,
                        "Failed to change permissions on %s directory",
                        dircheck[i].dir);
                exit(1);
            }
        }
    }

    /* check if token directory is available, if not flag an error.
     * We do not create token directories here as admin should
     * configure and decide which tokens to expose to opencryptoki
     * outside of opencryptoki and pkcsslotd */
    ec = stat(CONFIG_PATH, &sbuf);
    if (ec != 0 && errno == ENOENT) {
        fprintf(stderr, "Token directories missing\n");
        exit(2);
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

int chk_create_tokdir(Slot_Info_t_64 *psinfo)
{
    struct stat sbuf;
    char tokendir[PATH_MAX];
    struct group *grp;
    gid_t grpid;
    int uid, rc;
    mode_t proc_umask;
    char *tokdir = psinfo->tokname;
    char token_md5_hash[MD5_HASH_SIZE];

    /* skip if no dedicated token directory is required */
    if (!tokdir || strlen(tokdir) == 0)
        return 0;

    /* Check if the path length fits in the max path length
       (include 2 * / and 0)
     */
    if (strlen(CONFIG_PATH) + strlen(tokdir) + strlen(OBJ_DIR) + 3 > PATH_MAX) {
        fprintf(stderr, "Path name for token object directory too long!\n");
        return -1;
    }

    proc_umask = umask(0);

    /* get 'PKCS11' group id */
    uid = (int) geteuid();
    grp = getgrnam("pkcs11");
    if (!grp) {
        fprintf(stderr, "PKCS11 group does not exist [errno=%d].\n", errno);
        return errno;
    } else {
        grpid = grp->gr_gid;
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
    if (rc != 0 && errno == ENOENT) {
        /* directory does not exist, create it */
        rc = mkdir(tokendir, S_IRWXU | S_IRWXG);
        if (rc != 0) {
            fprintf(stderr,
                    "Creating directory '%s' failed [errno=%d].\n",
                    tokendir, errno);
            umask(proc_umask);
            return rc;
        }

        rc = chown(tokendir, uid, grpid);
        if (rc != 0) {
            fprintf(stderr,
                    "Could not set PKCS11 group permission [errno=%d].\n",
                    errno);
            umask(proc_umask);
            return rc;
        }

    }

    /* Create TOK_OBJ directory */
    /* sprintf checked above */
    sprintf(tokendir, "%s/%s/%s", CONFIG_PATH, tokdir, OBJ_DIR);
    rc = stat(tokendir, &sbuf);
    if (rc != 0 && errno == ENOENT) {
        /* directory does not exist, create it */
        rc = mkdir(tokendir, S_IRWXU | S_IRWXG);
        if (rc != 0) {
            fprintf(stderr,
                    "Creating directory '%s' failed [errno=%d].\n",
                    tokendir, errno);
            umask(proc_umask);
            return rc;
        }

        rc = chown(tokendir, uid, grpid);
        if (rc != 0) {
            fprintf(stderr,
                    "Could not set PKCS11 group permission [errno=%d].\n",
                    errno);
            umask(proc_umask);
            return rc;
        }
    }
    umask(proc_umask);
    return 0;
}

static int create_pid_file(pid_t pid)
{
    FILE *pidfile;

    pidfile = fopen(PID_FILE_PATH, "w");
    if (!pidfile) {
        fprintf(stderr, "Could not create pid file '%s' [errno=%d].\n",
                PID_FILE_PATH, errno);
        return -1;
    }

    fprintf(pidfile, "%d\n", (int) pid);
    fflush(pidfile);
    fclose(pidfile);
    InfoLog("PID File created");

    return 0;
}

/*************************
 * Parser callouts
 ************************/
static int slotmgr_begin_slot(void *private, int slot, int nl_before_slot)
{
    struct parse_data *d = (struct parse_data *)private;

    UNUSED(nl_before_slot);
    memset(&d->sinfo_struct, 0, sizeof(d->sinfo_struct));
    if (slot >= NUMBER_SLOTS_MANAGED) {
        snprintf(d->errbuf, sizeof(d->errbuf),
                "Slot number %d unsupported!  Slot number has to be less than %d!",
                slot, NUMBER_SLOTS_MANAGED);
        return 1;
    }
    d->sinfo_struct.slot_number = slot;
    d->index = slot;
    return 0;
}

static int slotmgr_end_slot(void *private)
{
    struct parse_data *d = (struct parse_data *)private;

    /* set some defaults if user hasn't set these. */
	if (!d->sinfo_struct.pk_slot.slotDescription[0]) {
		memset(&d->sinfo_struct.pk_slot.slotDescription[0], ' ',
               sizeof(d->sinfo_struct.pk_slot.slotDescription));
		memcpy(&d->sinfo_struct.pk_slot.slotDescription[0],
			   DEF_SLOTDESC, strlen(DEF_SLOTDESC));
	}
	if (!d->sinfo_struct.pk_slot.manufacturerID[0]) {
		memset(&d->sinfo_struct.pk_slot.manufacturerID[0], ' ',
		       sizeof(d->sinfo_struct.pk_slot.manufacturerID));
		memcpy(&d->sinfo_struct.pk_slot.manufacturerID[0],
			   DEF_MANUFID, strlen(DEF_MANUFID));
	}
    memcpy(&(sinfo[d->index]), &d->sinfo_struct, sizeof(d->sinfo_struct));
    NumberSlotsInDB++;
    return 0;
}

static int do_str(struct parse_data *d, char *slotinfo, size_t size,
                  int tok, const char *val, char padding)
{
	if (strlen(val) > size) {
        snprintf(d->errbuf, sizeof(d->errbuf), "%s has too many characters\n",
                 keyword_token_to_str(tok));
		return -1;
	}
    memset(slotinfo, padding, size);
	memcpy(slotinfo, val, strlen(val));
	return 0;
}

static int do_vers(struct parse_data *d,
                   CK_VERSION *slotinfo, int kw, const char *val)
{
	char *dot;

	if (!val || !*val) {
		snprintf(d->errbuf, sizeof(d->errbuf), "%s has no value\n",
                 keyword_token_to_str(kw));
		return -1 ;
	}

    dot = strchr(val, '.');
    slotinfo->major = strtol(val, NULL, 10);
    slotinfo->minor = dot ? strtol(dot + 1, NULL, 10) : 0;
	return 0;
}

static int slotmgr_key_str(void *private, int tok, const char *val)
{
    struct parse_data *d = (struct parse_data *)private;
    CK_VERSION vers;
    int res = 0;

    switch (tok) {
    case KW_STDLL:
        if (do_str(d, (char *)&d->sinfo_struct.dll_location,
                   sizeof(d->sinfo_struct.dll_location), tok, val, 0))
            res = 1;
        else
            d->sinfo_struct.present = TRUE;
        break;
    case KW_SLOTDESC:
        if (do_str(d, (char *)d->sinfo_struct.pk_slot.slotDescription,
                   sizeof(d->sinfo_struct.pk_slot.slotDescription), tok, val, ' '))
            res = 1;
        break;
    case KW_MANUFID:
        if (do_str(d, (char *)d->sinfo_struct.pk_slot.manufacturerID,
                   sizeof(d->sinfo_struct.pk_slot.manufacturerID), tok, val, ' '))
            res = 1;
        break;
    case KW_CONFNAME:
        if (do_str(d, (char *)d->sinfo_struct.confname,
                   sizeof(d->sinfo_struct.confname), tok, val, 0))
            res = 1;
        break;
    case KW_TOKNAME:
        if (do_str(d, (char *)d->sinfo_struct.tokname,
                   sizeof(d->sinfo_struct.tokname), tok, val, 0))
            res = 1;
        break;
    case KW_HWVERSION:
        if (do_vers(d, &d->sinfo_struct.pk_slot.hardwareVersion, tok, val))
            res = 1;
        break;
    case KW_FWVERSION:
        if (do_vers(d, &d->sinfo_struct.pk_slot.firmwareVersion, tok, val))
            res = 1;
        break;
    case KW_TOKVERSION:
        if (do_vers(d, &vers, tok, val))
            res = 1;
        else
            d->sinfo_struct.version = vers.major << 16 | vers.minor;
        break;
    default:
        snprintf(d->errbuf, sizeof(d->errbuf),
                 "Unknown string-valued keyword detected: \"%s\"",
                 keyword_token_to_str(tok));
        res = 1;
        break;
    }
    return res;
}

static int slotmgr_key_vers(void *private, int tok, unsigned int vers)
{
    struct parse_data *d = (struct parse_data *)private;

    switch (tok) {
    case KW_TOKVERSION:
        d->sinfo_struct.version = vers;
        return 0;
    case KW_HWVERSION:
        d->sinfo_struct.pk_slot.hardwareVersion.major = vers >> 16;
        d->sinfo_struct.pk_slot.hardwareVersion.minor = vers & 0xffu;
        return 0;
    case KW_FWVERSION:
        d->sinfo_struct.pk_slot.firmwareVersion.major = vers >> 16;
        d->sinfo_struct.pk_slot.firmwareVersion.minor = vers & 0xffu;
        return 0;
    }
    snprintf(d->errbuf, sizeof(d->errbuf),
             "Unkown version-valued keyword detected: \"%s\"",
             keyword_token_to_str(tok));
    return 1;
}

static void slotmgr_disab_event_supp(void *private)
{
    UNUSED(private);

    event_support_disabled = 1;
}

static void slotmgr_parseerror(void *private, int line, const char *parsermsg)
{
    struct parse_data *d = (struct parse_data *)private;

    ErrLog("Error parsing config file: line %d: %s\n",
           line, parsermsg ? parsermsg : d->errbuf);
}

static struct parsefuncs slotmgr_parsefuncs = {
    .begin_slot = slotmgr_begin_slot,
    .end_slot   = slotmgr_end_slot,
    .key_str    = slotmgr_key_str,
    .key_vers   = slotmgr_key_vers,
    .disab_event_supp = slotmgr_disab_event_supp,
    .parseerror = slotmgr_parseerror
};

/*****************************************
 *  main() -
 *      You know what main does.
 *      Comment block for ease of spotting
 *      it when paging through file
 *
 *****************************************/

int main(int argc, char *argv[], char *envp[])
{
    int ret, i;
    struct parse_data parsedata;

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

    ret = load_and_parse(OCK_CONFIG, &slotmgr_parsefuncs, &parsedata);
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

    if (!init_socket_server(event_support_disabled)) {
        DestroyMutexes();
        DetachFromSharedMemory();
        DestroySharedMemory();
        return 5;
    }

    if (!init_socket_data(&socketData)) {
        term_socket_server();
        DestroyMutexes();
        DetachFromSharedMemory();
        DestroySharedMemory();
        return 6;
    }
    if (event_support_disabled)
        socketData.flags |= FLAG_EVENT_SUPPORT_DISABLED;

    /* Create customized token directories */
    psinfo = &socketData.slot_info[0];
    for (i = 0; i < NUMBER_SLOTS_MANAGED; i++, psinfo++) {
        ret = chk_create_tokdir(psinfo);
        if (ret)
            return EACCES;
    }

    /*
     *  Become a Daemon, if called for
     */
    if (Daemon) {
        pid_t pid;
        if ((pid = fork()) < 0) {
            term_socket_server();
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
    if (!SetupSignalHandlers()) {
        term_socket_server();
        DestroyMutexes();
        DetachFromSharedMemory();
        DestroySharedMemory();
        return 8;
    }

    /* ultimatly we will create a couple of threads which monitor the slot db
     * and handle the insertion and removal of tokens from the slot.
     */

    /* For Testing the Garbage collection routines */
    /*
     * shmp->proc_table[3].inuse = TRUE;
     * shmp->proc_table[3].proc_id = 24328;
     */

#if !defined(NOGARBAGE)
    /* start garbage collection thread */
    if (!StartGCThread(shmp)) {
        term_socket_server();
        DestroyMutexes();
        DetachFromSharedMemory();
        DestroySharedMemory();
        return 9;
    }
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
     * Here we need to actualy go through the processes and verify that thye
     * still exist.  If not, then they terminated with out properly calling
     * C_Finalize and therefore need to be removed from the system.
     * Look for a system routine to determine if the shared memory is held by
     * the process to further verify that the proper processes are in the
     * table.
     *
     **************************************************************/
}                               /* end main */
