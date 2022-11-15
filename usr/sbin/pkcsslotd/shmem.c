/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <grp.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "slotmgr.h"
#include "log.h"
#include "pkcsslotd.h"

#define MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
#define MAPFILENAME CONFIG_PATH "/.apimap"

pthread_mutexattr_t mtxattr;    // Mutex attribute for the shared memory Mutex

/***********************************************************************
 *  CreateSharedMemory -
 *
 *      Creates and initializes a shared memory file.  This function will fail
 *      if the memory is already allocated since we're the owner of it.
 *
 ***********************************************************************/

int CreateSharedMemory(void)
{
    struct stat statbuf;
    char *Path = NULL;
    struct group *grp;
    struct shmid_ds shm_info;

#if !MMAP
    /*
     * getenv() is safe here since we will exclusively create the segment and
     * make sure only members of pkcs11 group can attach to it.
     */
    if (((Path = getenv("PKCS11_SHMEM_FILE")) == NULL) || (Path[0] == '\0')) {
        Path = TOK_PATH;
    }

    // Get shared memory key token all users of the shared memory
    // need to get the same token

    if (stat(Path, &statbuf) < 0) {
        ErrLog("Shared Memory Key Token creation file does not exist");
        return FALSE;
    }
    // SAB  Get the group information for the PKCS#11 group... fail if
    // it does not exist
    grp = getgrnam(PKCS_GROUP);
    if (!grp) {
        ErrLog("Group %s does not exist ", PKCS_GROUP);
        return FALSE;           // Group does not exist... setup is wrong..
    }


    tok = ftok(Path, 'b');
    // Allocate the shared memory... Fail if the memory is already
    // allocated since the slot mgr is the owner of it.

    // Is this some attempt at exclusivity, or is that just a side effect?
    // - SCM 9/1

    shmid = shmget(tok, sizeof(Slot_Mgr_Shr_t),
                   IPC_CREAT | IPC_EXCL | S_IRUSR |
                   S_IRGRP | S_IWUSR | S_IWGRP);

    // Explanation of options to shmget():

    /*
     *  IPC_CREAT Creates the data structure if it does not already exist.
     *  IPC_EXCL  Causes the shmget subroutine to be unsuccessful if the
     *            IPC_CREAT flag is also set, and the data structure already
     *            exists.
     *  S_IRUSR   Permits the process that owns the data structure to read it.
     *  S_IWUSR   Permits the process that owns the data structure to modify it.
     *  S_IRGRP   Permits the group associated with the data structure to
     *            read it.
     *  S_IWGRP   Permits the group associated with the data structure to
     *            modify it.
     *
     *
     *  WE DON"T WANT OTHERS
     *  S_IROTH   Permits others to read the data structure.
     *  S_IWOTH   Permits others to modify the data structure.
     */


    if (shmid < 0) {
        ErrLog("Shared memory creation failed (0x%X)\n", errno);
        ErrLog("Reclaiming 0x%X\n", tok);
        shmid = shmget(tok, sizeof(Slot_Mgr_Shr_t), 0);
        DestroySharedMemory();
        shmid = shmget(tok, sizeof(Slot_Mgr_Shr_t),
                       IPC_CREAT | IPC_EXCL | S_IRUSR |
                       S_IRGRP | S_IWUSR | S_IWGRP);
        if (shmid < 0) {
            ErrLog("Shared memory reclamation failed (0x%X)\n", errno);
            ErrLog("perform ipcrm -M 0x%X\n", tok);
            return FALSE;
        }
    }
    // SAB Set the group ownership of the shared mem segment..
    // we already have the group structure..

    if (shmctl(shmid, IPC_STAT, &shm_info) == 0) {

        shm_info.shm_perm.gid = grp->gr_gid;

        if (shmctl(shmid, IPC_SET, &shm_info) == -1) {
            ErrLog("Failed to set group ownership for shm \n");
            shmctl(shmid, IPC_RMID, NULL);
            // Not safe to use this segment
            return FALSE;
        }

    } else {
        ErrLog("Can't get status of shared memory %d\n", errno);
        // we know it was created... we need to destroy it...
        shmctl(shmid, IPC_RMID, NULL);
        // Not safe to use this segment
        return FALSE;
    }

    return TRUE;
#else
    {
#warning "EXPERIMENTAL"
        int fd;
        int i;
        char *buffer;

        grp = getgrnam(PKCS_GROUP);
        if (!grp) {
            ErrLog("Group \"%s\" does not exist! "
                   "Opencryptoki setup is incorrect.", PKCS_GROUP);
            return FALSE;       // Group does not exist... setup is wrong..
        }

        fd = open(MAPFILENAME, O_RDWR, MODE);
        if (fd < 0) {
            // File does not exist... this is cool, we creat it here
            fd = open(MAPFILENAME, O_RDWR | O_CREAT, MODE); // Create the file
            if (fd < 0) {   // We are really hosed here, since we should be able
                // to create the file now
                ErrLog("%s: open(%s): %s", __func__, MAPFILENAME,
                       strerror(errno));
                return FALSE;
            } else {
                if (fchmod(fd, MODE) == -1) {
                    ErrLog("%s: fchmod(%s): %s", __func__, MAPFILENAME,
                           strerror(errno));
                    close(fd);
                    return FALSE;
                }
                if (fchown(fd, 0, grp->gr_gid) == -1) {
                    ErrLog("%s: fchown(%s, root, %s): %s", __func__,
                           MAPFILENAME, PKCS_GROUP, strerror(errno));
                    close(fd);
                    return FALSE;
                }
                // Create a buffer and make the file the right length
                i = sizeof(Slot_Mgr_Shr_t);
                buffer = malloc(sizeof(Slot_Mgr_Shr_t));
                memset(buffer, '\0', i);
                write(fd, buffer, i);
                free(buffer);
                close(fd);
            }
        } else {
            ErrLog("%s: [%s] exists; you may already have a pkcsslot daemon "
                   "running. If this is not the case, then the prior daemon "
                   "was not shut down cleanly. Please delete this file and "
                   "try again\n", __func__, MAPFILENAME);
            close(fd);
            return FALSE;
        }
        return TRUE;
    }

#endif

}




/***********************************************************************
 *
 * AttachToSharedMemory -
 *
 *     Called after creating the shared memory file
 *     Basically allows us to have access to the memory we've just created
 *
 ***********************************************************************/

int AttachToSharedMemory(void)
{

#if !MMAP
    shmp = NULL;
    shmp = (Slot_Mgr_Shr_t *) shmat(shmid, NULL, 0);

    if (!shmp) {
        ErrLog("Shared memory attach failed (0x%X)\n", errno);
        return FALSE;
    }

    /* Initizalize the memory to 0  */
    memset(shmp, '\0', sizeof(*shmp));

    return TRUE;
#else
    {
#warning "EXPERIMENTAL"
        int fd;
        int i;
        char *buffer;

        fd = open(MAPFILENAME, O_RDWR, MODE);
        if (fd < 0) {
            return FALSE;       //Failed
        }
        shmp =
            (Slot_Mgr_Shr_t *) mmap(NULL, sizeof(Slot_Mgr_Shr_t),
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        if (!shmp) {
            return FALSE;
        }
        return TRUE;
    }
#endif

}



/***********************************************************************
 *
 * DetachFromSharedMemory -
 *
 *     Un-does AttachToSharedMemory() :)
 *
 ***********************************************************************/

void DetachFromSharedMemory(void)
{

#if !MMAP
    if (shmp == NULL)
        return;

    if (shmdt(shmp) != 0) {
        ErrLog("Attempted to detach from an invalid shared memory pointer");
    }

    shmp = NULL;
    return;
#else
    if (shmp == NULL)
        return;

    munmap((void *) shmp, sizeof(*shmp));

    unlink(MAPFILENAME);
#endif

}


/***********************************************************************
 *
 * DestroySharedMemory -
 *
 *     Closes (destroys) the shared memory file we created with
 *     CreateSharedMemory()
 *
 *     We should make sure that everyone else has detached before we do this
 *     if we manage to exit before this gets called, you have to call ipcrm
 *     to clean things up...
 *
 ***********************************************************************/

void DestroySharedMemory(void)
{
    if (shmctl(shmid, IPC_RMID, 0) != 0) {
        perror("error in closing shared memory segment");
    }

    return;
}



/***********************************************************************
 *
 * InitSharedMemory -
 *
 *      Set up our newly allocated shared memory segment
 *
 *
 ***********************************************************************/


int InitSharedMemory(Slot_Mgr_Shr_t *sp)
{
    uint16 procindex;

    memset(sp->slot_global_sessions, 0, NUMBER_SLOTS_MANAGED * sizeof(uint32));
    memset(sp->slot_global_rw_sessions, 0, NUMBER_SLOTS_MANAGED * sizeof(uint32));

    /* Initialize the process side of things. */
    /* for now don't worry about the condition variables */
    for (procindex = 0; procindex < NUMBER_PROCESSES_ALLOWED; procindex++) {
        /* Initialize the mutex variables. */
        sp->proc_table[procindex].inuse = FALSE;
    }

    return TRUE;
}
