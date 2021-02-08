/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* (C) COPYRIGHT Google Inc. 2013 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <grp.h>

#include "log.h"
#include "slotmgr.h"
#include "pkcsslotd.h"
#include "apictl.h"

int proc_listener_socket = -1;

static void close_listener_socket(int socketfd, const char *file_path);

// Creates the daemon's listener socket, to which clients will connect and
// retrieve slot information through.  Returns the file descriptor of the
// created socket.
static int create_listener_socket(const char *file_path)
{
    struct sockaddr_un address;
    struct group *grp;
    int socketfd;

    socketfd = socket(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (socketfd < 0) {
        ErrLog("Failed to create listener socket, errno 0x%X.", errno);
        return -1;
    }
    if (unlink(file_path) && errno != ENOENT) {
        ErrLog("Failed to unlink socket file, errno 0x%X.", errno);
        goto error;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, file_path);

    if (bind(socketfd,
             (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
        ErrLog("Failed to bind to socket, errno 0x%X.", errno);
        goto error;
    }
    // make socket file part of the pkcs11 group, and write accessable
    // for that group
    grp = getgrnam("pkcs11");
    if (!grp) {
        ErrLog("Group PKCS#11 does not exist");
        goto error;
    }
    if (chown(file_path, 0, grp->gr_gid)) {
        ErrLog("Could not change file group on socket, errno 0x%X.", errno);
        goto error;
    }
    if (chmod(file_path,
              S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP)) {
        ErrLog("Could not change file permissions on socket, errno 0x%X.",
               errno);
        goto error;
    }

    if (listen(socketfd, 20) != 0) {
        ErrLog("Failed to listen to socket, errno 0x%X.", errno);
        goto error;
    }

    return socketfd;

error:
    if (socketfd >= 0)
        close_listener_socket(socketfd, file_path);

    return -1;
}


static void close_listener_socket(int socketfd, const char *file_path)
{
    close(socketfd);
    unlink(file_path);
}

int init_socket_data(Slot_Mgr_Socket_t *socketData)
{
    unsigned int processed = 0;

    PopulateCKInfo(&(socketData->ck_info));
    socketData->num_slots = NumberSlotsInDB;
    PopulateSlotInfo(socketData->slot_info, &processed);

    /* check that we read in correct amount of slots */
    if (processed != NumberSlotsInDB) {
        ErrLog("Failed to populate slot info.\n");
        return FALSE;
    }

    return TRUE;
}

int socket_connection_handler(int timeout_secs)
{
    int returnVal;
    fd_set set;
    struct timeval timeout;

    FD_ZERO(&set);
    FD_SET(proc_listener_socket, &set);

    timeout.tv_sec = timeout_secs;
    timeout.tv_usec = 0;

    returnVal = select(proc_listener_socket + 1, &set, NULL, NULL, &timeout);
    if (returnVal == -1) {
        ErrLog("select failed on socket connection, errno 0x%X.", errno);
        return FALSE;
    } else if (returnVal == 0) {
        // select call timed out, return
        return FALSE;
    } else {
        struct sockaddr_un address;
        socklen_t address_length = sizeof(address);

        int connectionfd = accept(proc_listener_socket,
                                  (struct sockaddr *) &address,
                                  &address_length);
        if (connectionfd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                /* These errors are allowed since
                 * socket is non-blocking
                 */
                ErrLog("Failed to accept socket connection, errno 0x%X.",
                       errno);
            }
            return FALSE;
        }

        DbgLog(DL0, "Accepted connection from process: socket: %d", 
               connectionfd);

        if (write(connectionfd, &socketData, sizeof(socketData)) !=
            sizeof(socketData)) {
            ErrLog("Failed to write socket data, errno 0x%X.", errno);
            close(connectionfd);
            return FALSE;
        }
        close(connectionfd);
        return TRUE;
    }
}

int init_socket_server()
{
    proc_listener_socket = create_listener_socket(PROC_SOCKET_FILE_PATH);
    if (proc_listener_socket < 0)
        return FALSE;

    DbgLog(DL0, "Socket server started");

    return TRUE;
}

int term_socket_server()
{
    if (proc_listener_socket >= 0)
        close_listener_socket(proc_listener_socket, PROC_SOCKET_FILE_PATH);

    DbgLog(DL0, "Socket server stopped");

    return TRUE;
}
