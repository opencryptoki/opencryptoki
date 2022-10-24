/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* (C) COPYRIGHT Google Inc. 2013 */

//
// Pkcs11 Api Socket client routines
//

#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <poll.h>

#include "apiproto.h"
#include "slotmgr.h"
#include "apictl.h"
#include "trace.h"
#include "ock_syslog.h"
#include "events.h"

extern API_Proc_Struct_t *Anchor;

int connect_socket(const char *file_path)
{
    int socketfd;
    struct sockaddr_un daemon_address;
    struct stat file_info;
    struct group *grp;
    struct passwd *pwd;

    if (stat(file_path, &file_info)) {
        OCK_SYSLOG(LOG_ERR,
                   "connect_socket: failed to find socket file, errno=%d",
                   errno);
        return -1;
    }

    grp = getgrnam("pkcs11");
    if (!grp) {
        OCK_SYSLOG(LOG_ERR,
                   "connect_socket: pkcs11 group does not exist, errno=%d",
                   errno);
        return -1;
    }

    pwd = getpwnam("pkcsslotd");
    if (!pwd) {
        OCK_SYSLOG(LOG_ERR,
                   "connect_socket: pkcsslotd user does not exist, errno=%d",
                   errno);
        return -1;
    }

    if (file_info.st_uid != pwd->pw_uid || file_info.st_gid != grp->gr_gid) {
        OCK_SYSLOG(LOG_ERR,
                   "connect_socket: incorrect permissions on socket file");
        return -1;
    }

    if ((socketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        OCK_SYSLOG(LOG_ERR,
                   "connect_socket: failed to create socket, errno=%d",
                   errno);
        return -1;
    }

    memset(&daemon_address, 0, sizeof(struct sockaddr_un));
    daemon_address.sun_family = AF_UNIX;
    strncpy(daemon_address.sun_path, file_path,
            sizeof(daemon_address.sun_path));
    daemon_address.sun_path[sizeof(daemon_address.sun_path) - 1] = '\0';

    if (connect(socketfd, (struct sockaddr *) &daemon_address,
                sizeof(struct sockaddr_un)) != 0) {
        OCK_SYSLOG(LOG_ERR,
                   "connect_socket: failed to connect to slotmanager daemon, "
                   "errno=%d",
                   errno);
        goto error;
    }

    return socketfd;

error:
    close(socketfd);
    return -1;
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

//
// Will fill out the Slot_Mgr_Socket_t and Slot_Mgr_Client_Cred_t structures
// in the Anchor global data structure with the values passed by the pkcsslotd
// via a socket RPC.
int init_socket_data(int socketfd)
{
    ssize_t n;

    n = read_all(socketfd, (char *)&Anchor->ClientCred,
                 sizeof(Anchor->ClientCred));
    if (n < 0) {
        // read error
        OCK_SYSLOG(LOG_ERR, "init_socket_data: read error \
                   on daemon socket, errno=%zd", -n);
        return FALSE;
    }
    if (n != sizeof(Anchor->ClientCred)) {
        // eof but we still expect some bytes
        OCK_SYSLOG(LOG_ERR, "init_socket_data: read returned \
                   with eof but we still \
                   expect %lu bytes from daemon",
                   sizeof(Anchor->ClientCred) - n);
        return FALSE;
    }

    n = read_all(socketfd, (char *)&Anchor->SocketDataP,
                 sizeof(Anchor->SocketDataP));
    if (n < 0) {
        // read error
        OCK_SYSLOG(LOG_ERR, "init_socket_data: read error \
                   on daemon socket, errno=%zd", -n);
        return FALSE;
    }
    if (n != sizeof(Anchor->SocketDataP)) {
        // eof but we still expect some bytes
        OCK_SYSLOG(LOG_ERR, "init_socket_data: read returned \
                   with eof but we still \
                   expect %lu bytes from daemon",
                   sizeof(Anchor->SocketDataP) - n);
        return FALSE;
    }

    return TRUE;
}

static bool match_token_label_filter(event_msg_t *event, API_Slot_t *sltp)
{
    if (event->token_label[0] == ' ' || event->token_label[0] == '\0')
        return true;

    return memcmp(event->token_label,
                  sltp->TokData->nv_token_data->token_info.label,
                  sizeof(event->token_label)) == 0;
}

struct type_model {
    unsigned int type;
    char model[member_size(CK_TOKEN_INFO_32, model)];
};

static const struct type_model type_model_flt[] = {
        { .type = EVENT_TOK_TYPE_CCA,  .model = "CCA             " },
        { .type = EVENT_TOK_TYPE_EP11, .model = "EP11            " },
};

static bool match_token_type_filter(event_msg_t *event, API_Slot_t *sltp)
{
    size_t i;

    if (event->token_type == EVENT_TOK_TYPE_ALL)
        return true;

    for (i = 0; i < sizeof(type_model_flt) / sizeof(struct type_model); i++) {
        if (memcmp(sltp->TokData->nv_token_data->token_info.model,
                   type_model_flt[i].model,
                   sizeof(type_model_flt[i].model)) == 0 &&
            (event->token_type & type_model_flt[i].type) != 0)
            return true;
    }

    return false;
}

static int handle_event(API_Proc_Struct_t *anchor, event_msg_t *event,
                        char *payload, event_reply_t *reply)
{
    CK_SLOT_ID slotID;
    API_Slot_t *sltp;
    CK_RV rc;

    /* If its not for our process, ignore it, don't increment reply counters */
    if (event->process_id != 0 &&
        event->process_id != anchor->ClientCred.real_pid)
        return 0;

    for (slotID = 0; slotID < NUMBER_SLOTS_MANAGED; slotID++) {
        sltp = &anchor->SltList[slotID];
        if (sltp->DLLoaded == FALSE || sltp->FcnList == NULL)
            continue;

        if (!match_token_label_filter(event, sltp))
            continue;
        if (!match_token_type_filter(event, sltp))
            continue;

        if (sltp->FcnList->ST_HandleEvent != NULL)
            rc = sltp->FcnList->ST_HandleEvent(sltp->TokData, event->type,
                                               event->flags, payload,
                                               event->payload_len);
        else
            rc = CKR_FUNCTION_NOT_SUPPORTED;

        TRACE_DEVEL("Slot %lu ST_HandleEvent rc: 0x%lx\n", slotID, rc);
        switch (rc) {
        case CKR_OK:
            reply->positive_replies++;
            break;
        case CKR_FUNCTION_NOT_SUPPORTED:
            reply->nothandled_replies++;
            break;
        default:
            reply->negative_replies++;
            break;
        }
    }

    return 0;
}

struct cleanup_data {
    API_Proc_Struct_t *anchor;
#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_LIB_CTX *prev_libctx;
#endif
};

static void event_thread_cleanup(void *arg)
{
    struct cleanup_data *cleanup = arg;

#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_LIB_CTX_set0_default(cleanup->prev_libctx);
#else
    UNUSED(cleanup);
#endif

    TRACE_DEVEL("Event thread %lu terminating\n", pthread_self());
}

static void *event_thread(void *arg)
{
    API_Proc_Struct_t *anchor = arg;
    struct cleanup_data cleanup;
#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_LIB_CTX *prev_libctx;
#endif
    int oldstate, oldtype;
    struct pollfd pollfd;
    event_msg_t event;
    char *payload;
    event_reply_t reply;
    ssize_t num;
    int rc;

    UNUSED(arg);

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

    TRACE_DEVEL("Event thread %lu running\n", pthread_self());

    if (anchor->socketfd < 0) {
        TRACE_ERROR("socket is already closed.\n");
        TRACE_DEVEL("Event thread %lu terminating\n", pthread_self());
        return NULL;
    }

#if OPENSSL_VERSION_PREREQ(3, 0)
    /* Ensure that the event thread uses Opencryptoki's own library context */
    prev_libctx = OSSL_LIB_CTX_set0_default(Anchor->openssl_libctx);
    if (prev_libctx == NULL) {
        TRACE_ERROR("OSSL_LIB_CTX_set0_default failed\n");
        TRACE_DEVEL("Event thread %lu terminating\n", pthread_self());
        return NULL;
    }
#endif

    /* Enable cancellation */
    cleanup.anchor = anchor;
#if OPENSSL_VERSION_PREREQ(3, 0)
    cleanup.prev_libctx = prev_libctx;
#endif
    pthread_cleanup_push(event_thread_cleanup, &cleanup);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);

    pollfd.fd = anchor->socketfd;
    pollfd.events = POLLIN | POLLHUP | POLLERR;

    while (1) {
        pollfd.revents = 0;
        rc = poll(&pollfd, 1, -1);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
            TRACE_ERROR("poll failed: %d\n", errno);
            break;
        }

        if (rc == 0)
            continue;

        if (pollfd.revents & (POLLHUP | POLLERR)) {
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
            TRACE_ERROR("Error on socket, possibly closed by slot daemon\n");
            break;
        }
        if ((pollfd.revents & POLLIN) == 0)
            continue;

        /* Disable for cancellation while we are working on an event */
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

        TRACE_DEVEL("Receive new event ....\n");

        num = read_all(anchor->socketfd, (char *)&event, sizeof(event));
        if (num != sizeof(event)) {
            TRACE_ERROR("Error receiving the event, rc: %ld\n", num);
            break;
        }

        TRACE_DEBUG("Event version:      %u\n", event.version);
        TRACE_DEBUG("Event type:         0x%08x\n", event.type);
        TRACE_DEBUG("Event flags:        0x%08x\n", event.flags);
        TRACE_DEBUG("Event token_type:   0x%08x\n", event.token_type);
        TRACE_DEBUG("Event token_name:   '%.32s'\n", event.token_label);
        TRACE_DEBUG("Event process_id:   %u\n", event.process_id);
        TRACE_DEBUG("Event payload_len:  %u\n", event.payload_len);

        if (event.version != EVENT_VERSION_1) {
            TRACE_ERROR("Event version invalid: %u\n", event.version);
            break;
        }

        payload = NULL;
        if (event.payload_len > 0) {
            payload = malloc(event.payload_len);
            if (payload == NULL) {
                TRACE_ERROR("Failed to allocate buffer for event payload\n");
                break;
            }

            num = read_all(anchor->socketfd, payload, event.payload_len);
            if (num != event.payload_len) {
                TRACE_ERROR("Error receiving the event payload, rc: %ld\n", num);
                if (payload != NULL)
                    free(payload);
                break;
            }

            TRACE_DEBUG("Event payload:\n");
            TRACE_DEBUG_DUMP("  ", payload, event.payload_len);
        }

        memset(&reply, 0, sizeof(reply));
        reply.version = EVENT_VERSION_1;
        rc = handle_event(anchor, &event, payload, &reply);
        if (rc != 0) {
            TRACE_ERROR("Error handling the event, rc: %d\n", rc);
            if (payload != NULL)
                free(payload);
            break;
        }

        TRACE_DEBUG("Reply version:      %u\n", reply.version);
        TRACE_DEBUG("Reply positive:     %u\n", reply.positive_replies);
        TRACE_DEBUG("Reply negative:     %u\n", reply.negative_replies);
        TRACE_DEBUG("Reply not-handled:  %u\n", reply.nothandled_replies);

        if (event.flags & EVENT_FLAGS_REPLY_REQ) {
            num = send_all(anchor->socketfd, (char *)&reply, sizeof(reply));
            if (num != sizeof(reply)) {
                TRACE_ERROR("Error sending the event reply, rc: %ld\n", num);
                if (payload != NULL)
                    free(payload);
                break;
            }
        }

        if (payload != NULL)
            free(payload);

        /* Re-enable for  and test if we got canceled in the meantime */
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
        pthread_testcancel();
    }

    /*
     * Close the socket if we encounter an unrecoverable error (e.g. received
     * invalid event) and stop the thread because of that.
     * If the thread is stopped via stop_event_thread(), then it gets canceled
     * via pthread_cancel(), and will not reach this place, thus the socket is
     * not closed. This is intended, and the socket will then be closed by
     * C_Finalize(). The atfork 'prepare' handler in the parent process also
     * stops the thread (via stop_event_thread()), and the socket must not be
     * closed in this case, because the thread is restarted in the atfork
     * 'parent' handler, and should continue to receive events from the
     * socket.
     */
    close(anchor->socketfd);
    anchor->socketfd = -1;

#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_LIB_CTX_set0_default(prev_libctx);
#endif

    pthread_cleanup_pop(1);
    return NULL;
}

int start_event_thread(void)
{
    int rc;

    rc =  pthread_create(&Anchor->event_thread, NULL, event_thread, Anchor);
    if (rc != 0) {
        OCK_SYSLOG(LOG_ERR, "start_event_thread: pthread_create failed, "
                   "errno=%d", rc);
        TRACE_ERROR("Failed to start event thread, errno=%d\n", rc);
        return rc;
    }

    TRACE_DEVEL("Event thread %lu has been started\n", Anchor->event_thread);
    return 0;
}

int stop_event_thread(void)
{
    int rc;
    void *status;

    TRACE_DEVEL("Canceling event thread %lu\n", Anchor->event_thread);
    rc = pthread_cancel(Anchor->event_thread);
    if (rc != 0 && rc != ESRCH)
        return rc;

    TRACE_DEVEL("Waiting for event thread %lu to terminate\n",
                Anchor->event_thread);
    rc = pthread_join(Anchor->event_thread, &status);
    if (rc != 0)
        return rc;

    if (status != PTHREAD_CANCELED) {
        TRACE_ERROR("Event thread was stopped, but did not return the "
                   "expected status\n");
    }

    TRACE_DEVEL("Event thread %lu has terminated\n", Anchor->event_thread);

    Anchor->event_thread = 0;
    return 0;
}
