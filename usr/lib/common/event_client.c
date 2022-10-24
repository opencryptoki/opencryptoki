/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include "slotmgr.h"
#include "event_client.h"

static int connect_socket(const char *file_path)
{
    int socketfd;
    struct sockaddr_un daemon_address;
    struct stat file_info;
    struct group *grp;
    struct passwd *pwd;
    int rc;

    if (stat(file_path, &file_info))
        return -errno;

    grp = getgrnam("pkcs11");
    if (!grp)
        return -errno;

    pwd = getpwnam("pkcsslotd");
    if (!pwd)
        return -errno;

    if (file_info.st_uid != pwd->pw_uid || file_info.st_gid != grp->gr_gid)
        return -EPERM;

    if ((socketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        return -errno;

    memset(&daemon_address, 0, sizeof(struct sockaddr_un));
    daemon_address.sun_family = AF_UNIX;
    strncpy(daemon_address.sun_path, file_path,
            sizeof(daemon_address.sun_path));
    daemon_address.sun_path[sizeof(daemon_address.sun_path) - 1] = '\0';

    if (connect(socketfd, (struct sockaddr *) &daemon_address,
                sizeof(struct sockaddr_un)) != 0) {
        rc = -errno;
        goto error;
    }

    return socketfd;

error:
    close(socketfd);
    return rc;
}

static ssize_t read_all(int socketfd, char *buffer, size_t size)
{
    size_t bytes_received = 0;
    ssize_t n;

    while (bytes_received < size) {
        n = read(socketfd, buffer + bytes_received, size - bytes_received);
        if (n < 0) {
            // read error
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            break;

        bytes_received += n;
    }

    return bytes_received;
}

static ssize_t send_all(int socketfd, char *buffer, size_t size)
{
    size_t bytes_sent = 0;
    ssize_t n;

    while (bytes_sent < size) {
        n = send(socketfd, buffer + bytes_sent, size - bytes_sent, 0);
        if (n < 0) {
            // send error
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            break;

        bytes_sent += n;
    }

    return bytes_sent;
}

/*
 * Initialize an admin connection to the pkcsslotd.
 * Returns a file descriptor representing the connection, or a negative errno
 * in case of an error.
 */
int init_event_client(void)
{
    int fd;

    fd = connect_socket(ADMIN_SOCKET_FILE_PATH);

    return fd;
}

/*
 * Send an event though the admin connection to the pkcsslotd, and thus to
 * all active token instances.
 * If parameter fd is < 0, then a connection to pkcsslotd is established
 * inside the function and closed before return. This is for a one shot event.
 * Otherwise, pass a file descriptor received from init_event_client(). This
 * is to send multiple events.
 * Event type is mandatory, flags can be zero.
 * The event payload is optional, if payload_len is non-zero, then payload must
 * point to a buffer containing the payload to send with the event.
 * The event destination can be used to selectively send the event to certain
 * token instances only. If destination is NULL, it is sent to all token
 * instances.
 * If flag EVENT_FLAGS_REPLY_REQ is on in the flags parameter, then it is waited
 * until all active token instances have replied. The combined result of the
 * replies from the token instances is returned in the reply structure.
 * Parameter reply must be non-NULL if flag EVENT_FLAGS_REPLY_REQ is set.
 * Returns zero for success, or a negative errno in case of an error. In most
 * error cases the connection to the pkcsslotd is out of sequence and can no
 * longer be used to send further events.
 */
int send_event(int fd, unsigned int type, unsigned int flags,
               unsigned int payload_len, const char *payload,
               const struct event_destination *destination,
               struct event_reply *reply)
{
    event_msg_t event_msg;
    event_reply_t event_reply;
    int rc, term = 0;

    if (payload_len > 0 && payload == NULL)
        return -EINVAL;
    if ((flags & EVENT_FLAGS_REPLY_REQ) && reply == NULL)
        return -EINVAL;
    if (payload_len > EVENT_MAX_PAYLOAD_LENGTH)
        return -EMSGSIZE;

    if (fd < 0) {
        fd = init_event_client();
        if (fd < 0)
            return fd;
        term = 1;
    }

    memset(&event_msg, 0, sizeof(event_msg));
    event_msg.version = EVENT_VERSION_1;
    event_msg.type = type;
    event_msg.flags = flags;
    if (destination != NULL) {
        event_msg.token_type = destination->token_type;
        memcpy(event_msg.token_label, destination->token_label,
               sizeof(event_msg.token_label));
        event_msg.process_id = destination->process_id;
    } else {
        memset(event_msg.token_label, ' ', sizeof(event_msg.token_label));
    }
    event_msg.payload_len = payload_len;

    rc = send_all(fd, (char *)&event_msg, sizeof(event_msg));
    if (rc < 0)
        goto out;

    if (payload_len > 0) {
        rc = send_all(fd, (char *)payload, payload_len);
        if (rc < 0)
            goto out;
    }

    if (flags & EVENT_FLAGS_REPLY_REQ) {
        rc = read_all(fd, (char *)&event_reply, sizeof(event_reply));
        if (rc < 0)
            goto out;

        reply->positive_replies = event_reply.positive_replies;
        reply->negative_replies = event_reply.negative_replies;
        reply->nothandled_replies = event_reply.nothandled_replies;
    }

    rc = 0;

out:
    if (term)
        term_event_client(fd);

    return rc;
}

/*
 * Terminate the admin connection to the pkcsslotd.
 */
void term_event_client(int fd)
{
    if (fd >= 0)
        close(fd);
}

