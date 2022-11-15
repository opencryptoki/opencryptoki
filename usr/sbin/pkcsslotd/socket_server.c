/*
 * COPYRIGHT (c) International Business Machines Corp. 2013, 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* (C) COPYRIGHT Google Inc. 2013 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <grp.h>
#include <sys/epoll.h>

#if defined(__GNUC__) && __GNUC__ >= 7 || defined(__clang__) && __clang_major__ >= 12
    #define FALL_THROUGH __attribute__ ((fallthrough))
#else
    #define FALL_THROUGH ((void)0)
#endif

#ifdef WITH_LIBUDEV
#include <libudev.h>
#endif

#include "log.h"
#include "slotmgr.h"
#include "pkcsslotd.h"
#include "apictl.h"
#include "dlist.h"
#include "events.h"

#define MAX_EPOLL_EVENTS            128

#ifdef WITH_LIBUDEV
#define UDEV_RECV_BUFFFER_SIZE      512 * 1024
#define UDEV_SUBSYSTEM_AP           "ap"
#define UDEV_ACTION_BIND            "bind"
#define UDEV_ACTION_UNBIND          "unbind"
#define UDEV_ACTION_CHANGE          "change"
#define UDEV_ACTION_DEVTYPE_APQN    "ap_queue"
#define UDEV_PROPERTY_DEVTYPE       "DEV_TYPE"
#define UDEV_PROPERTY_CONFIG        "CONFIG"
#define UDEV_PROPERTY_ONLINE        "ONLINE"
#endif

struct epoll_info {
    int (* notify)(int events, void *private);
    void (* free)(void *private);
    void *private;
    unsigned long ref_count;
};

struct listener_info {
    int socket;
    const char *file_path;
    int (* new_conn)(int socket, struct listener_info *listener);
    struct epoll_info ep_info;
    unsigned long num_clients;
    unsigned long max_num_clients;
};

enum xfer_state {
    XFER_IDLE = 0,
    XFER_RECEIVE = 1,
    XFER_SEND = 2,
};

struct client_info {
    int socket;
    int (* xfer_complete)(void *client);
    void (* hangup)(void *client);
    void (* free)(void *client);
    void *client;
    struct epoll_info ep_info;
    enum xfer_state xfer_state;
    char *xfer_buffer;
    size_t xfer_size;
    size_t xfer_offset;
};

enum proc_state {
    PROC_INITIAL_SEND = 0,
    PROC_INITIAL_SEND2 = 1,
    PROC_WAIT_FOR_EVENT = 2,
    PROC_SEND_EVENT = 3,
    PROC_SEND_PAYLOAD = 4,
    PROC_RECEIVE_REPLY = 5,
    PROC_HANGUP = 6,
};

struct proc_conn_info {
    struct client_info client_info;
    enum proc_state state;
    DL_NODE *events;
    struct event_info *event;
    event_reply_t reply;
    Slot_Mgr_Client_Cred_t client_cred;
};

enum admin_state {
    ADMIN_RECEIVE_EVENT = 0,
    ADMIN_RECEIVE_PAYLOAD = 1,
    ADMIN_EVENT_DELIVERED = 2,
    ADMIN_SEND_REPLY = 3,
    ADMIN_WAIT_FOR_EVENT_LIMIT = 4,
    ADMIN_HANGUP = 5,
};

struct admin_conn_info {
    struct client_info client_info;
    enum admin_state state;
    struct event_info *event;
};

#ifdef WITH_LIBUDEV
struct udev_mon {
    struct udev *udev;
    struct udev_monitor *mon;
    int socket;
    struct epoll_info ep_info;
    struct event_info *delayed_event;
};
#endif

struct event_info {
    event_msg_t event;
    char *payload;
    event_reply_t reply;
    unsigned long proc_ref_count;      /* # of processes using this event */
    struct admin_conn_info *admin_ref; /* Admin connection to send reply back */
};

static int epoll_fd = -1;
static struct listener_info proc_listener = { .socket = -1 };
static DL_NODE *proc_connections = NULL;
static struct listener_info admin_listener = { .socket = -1 };
static DL_NODE *admin_connections = NULL;
#ifdef WITH_LIBUDEV
static struct udev_mon udev_mon = { .socket = -1 };
#endif
static DL_NODE *pending_events = NULL;
static unsigned long pending_events_count = 0;

#define MAX_PENDING_EVENTS      1024

/*
 * Iterate over all connections in a safe way. Before actually iterating,
 * increment the ref count of ALL connections, because any processing may
 * cause any of the connections to be hang-up, and thus freed and removed
 * from the list. We need to make sure that while we are iterating over the
 * connections, none of them gets removed from the list.
 */
#define FOR_EACH_CONN_SAFE_BEGIN(list, conn) {                              \
        DL_NODE *_node, *_next;                                             \
        _node = dlist_get_first(list);                                      \
        while (_node != NULL) {                                             \
            conn = _node->data;                                             \
            _next = dlist_next(_node);                                      \
            client_socket_get(&(conn)->client_info);                        \
            _node = _next;                                                  \
        }                                                                   \
        _node = dlist_get_first(list);                                      \
        while (_node != NULL) {                                             \
            conn = _node->data;                                             \
            _next = dlist_next(_node);

#define FOR_EACH_CONN_SAFE_END(list, conn)                                  \
            _node = _next;                                                  \
        }                                                                   \
        _node = dlist_get_first(list);                                      \
        while (_node != NULL) {                                             \
            conn = _node->data;                                             \
            _next = dlist_next(_node);                                      \
            client_socket_put(&(conn)->client_info);                        \
            _node = _next;                                                  \
        }                                                                   \
    }



static void listener_socket_close(int socketfd, const char *file_path);
static int listener_client_hangup(struct listener_info *listener);
static void event_delivered(struct event_info *event);
static int client_socket_notify(int events, void *private);
static void client_socket_free(void *private);
static int proc_xfer_complete(void *client);
static int proc_start_deliver_event(struct proc_conn_info *conn);
static int proc_deliver_event(struct proc_conn_info *conn,
                              struct event_info *event);
static int proc_event_delivered(struct proc_conn_info *conn,
                                struct event_info *event);
static inline void proc_get(struct proc_conn_info *conn);
static inline void proc_put(struct proc_conn_info *conn);
static void proc_hangup(void *client);
static void proc_free(void *client);
static int admin_xfer_complete(void *client);
static void admin_event_limit_underrun(struct admin_conn_info *conn);
static int admin_event_delivered(struct admin_conn_info *conn,
                                 struct event_info **event);
static inline void admin_get(struct admin_conn_info *conn);
static inline void admin_put(struct admin_conn_info *conn);
static void admin_hangup(void *client);
static void admin_free(void *client);
#ifdef WITH_LIBUDEV
static void udev_mon_term(struct udev_mon *udev_mon);
static int udev_mon_notify(int events, void *private);
#endif

static void epoll_info_init(struct epoll_info *epoll_info,
                    int (* notify)(int events, void *private),
                    void (* free_cb)(void *private),
                    void *private)
{
    epoll_info->ref_count = 1;
    epoll_info->notify = notify;
    epoll_info->free = free_cb;
    epoll_info->private = private;
}

static void epoll_info_get(struct epoll_info *epoll_info)
{
    epoll_info->ref_count++;

    DbgLog(DL3, "%s: private: %p, ref_count: %lu", __func__,
           epoll_info->private, epoll_info->ref_count);
}

static void epoll_info_put(struct epoll_info *epoll_info)
{
    if (epoll_info->ref_count > 0)
        epoll_info->ref_count--;

    DbgLog(DL3, "%s: private: %p, ref_count: %lu", __func__,
           epoll_info->private, epoll_info->ref_count);

    if (epoll_info->ref_count == 0 && epoll_info->free != NULL)
        epoll_info->free(epoll_info->private);
}

static int client_socket_init(int socket, int (* xfer_complete)(void *client),
                              void (* hangup)(void *client),
                              void (* free_cb)(void *client), void *client,
                              struct client_info *client_info)
{
    struct epoll_event evt;
    int rc, err;

    if (xfer_complete == NULL || hangup == NULL)
        return -EINVAL;

    epoll_info_init(&client_info->ep_info, client_socket_notify,
                    client_socket_free, client_info);
    client_info->socket = socket;
    client_info->xfer_complete = xfer_complete;
    client_info->hangup = hangup;
    client_info->free = free_cb;
    client_info->client = client;
    client_info->xfer_state = XFER_IDLE;

    rc = fcntl(socket, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        err = errno;
        InfoLog("%s: Failed to set client socket %d to non-blocking, errno "
                "%d (%s).", __func__, socket, err, strerror(err));
        return -err;
    }

    evt.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLET;
    evt.data.ptr = &client_info->ep_info;
    rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket, &evt);
    if (rc != 0) {
        err = errno;
        InfoLog("%s: Failed to add client socket %d to epoll, errno %d (%s).",
                 __func__, socket, err, strerror(err));
        close(socket);
        return -err;
    }

    return 0;
}

static inline void client_socket_get(struct client_info *client_info)
{
    epoll_info_get(&client_info->ep_info);
}

static inline void client_socket_put(struct client_info *client_info)
{
    epoll_info_put(&client_info->ep_info);
}

static void client_socket_term(struct client_info *client_info)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_info->socket, NULL);
    close(client_info->socket);
    client_info->socket = -1;
}

static int client_socket_notify(int events, void *private)
{
    struct client_info *client_info = private;
    ssize_t num;
    int rc, err, socket = client_info->socket;

    DbgLog(DL3, "%s: Epoll event on client %p socket %d: events: 0x%x xfer: %d",
           __func__, client_info, socket, events, client_info->xfer_state);

    if (socket < 0)
        return -ENOTCONN;

    if (events & (EPOLLHUP | EPOLLERR)) {
        DbgLog(DL3, "EPOLLHUP | EPOLLERR");

        client_info->hangup(client_info->client);
        client_info = NULL; /* client_info may have been freed by now */
        return 0;
    }

    if (client_info->xfer_state == XFER_RECEIVE && (events & EPOLLIN)) {
        DbgLog(DL3, "%s: EPOLLIN: buffer: %p size: %lu ofs: %lu", __func__,
               client_info->xfer_buffer, client_info->xfer_size,
               client_info->xfer_offset);

        num = read(client_info->socket,
                   client_info->xfer_buffer + client_info->xfer_offset,
                   client_info->xfer_size - client_info->xfer_offset);
        if (num <= 0) {
            err = errno;

            DbgLog(DL3, "%s: read failed with: num: %ld errno: %d (%s)",
                   __func__, num, num < 0 ? err : 0,
                   num < 0 ? strerror(err) : "none");

            if (num < 0 && err == EWOULDBLOCK)
                return 0; /* Will be continued when socket becomes readable */

            /* assume connection closed by peer */
            client_info->hangup(client_info->client);
            client_info = NULL; /* client_info may have been freed by now */
            return 0;
        } else {
            DbgLog(DL3, "%s: %lu bytes received", __func__, num);

            client_info->xfer_offset += num;

            DbgLog(DL3, "%s: %lu bytes left", __func__,
                   client_info->xfer_size - client_info->xfer_offset);

            if (client_info->xfer_offset >= client_info->xfer_size) {
                client_info->xfer_state = XFER_IDLE;
                client_info->xfer_buffer = NULL;
                client_info->xfer_size = 0;
                client_info->xfer_offset = 0;

                client_socket_get(client_info);
                rc = client_info->xfer_complete(client_info->client);
                if (rc != 0) {
                    InfoLog("%s: xfer_complete callback failed for client "
                            "socket %d, rc: %d", __func__, socket,
                            rc);
                    client_info->hangup(client_info->client);
                }
                client_socket_put(client_info);
                client_info = NULL; /* client_info may have been freed by now */
                return rc;
            }
            return 0;
        }
    }

    if (client_info->xfer_state == XFER_SEND && (events & EPOLLOUT)) {
        DbgLog(DL3, "%s: EPOLLOUT: buffer: %p size: %lu ofs: %lu", __func__,
               client_info->xfer_buffer, client_info->xfer_size,
               client_info->xfer_offset);

        num = write(client_info->socket,
                    client_info->xfer_buffer + client_info->xfer_offset,
                    client_info->xfer_size - client_info->xfer_offset);
        if (num < 0) {
            err = errno;

            DbgLog(DL3, "%s: write failed with: errno: %d (%s)", __func__, err,
                   strerror(err));

            if (err == EWOULDBLOCK)
                return 0; /* Will be continued when socket becomes writable */

            /* assume connection closed by peer */
            client_info->hangup(client_info->client);
            client_info = NULL; /* client_info may have been freed by now */
            return 0;
        } else {
            DbgLog(DL3, "%s: %lu bytes sent", __func__, num);

            client_info->xfer_offset += num;

            DbgLog(DL3, "%s: %lu bytes left", __func__,
                   client_info->xfer_size - client_info->xfer_offset);

            if (client_info->xfer_offset >= client_info->xfer_size) {
                client_info->xfer_state = XFER_IDLE;
                client_info->xfer_buffer = NULL;
                client_info->xfer_size = 0;
                client_info->xfer_offset = 0;

                client_socket_get(client_info);
                rc = client_info->xfer_complete(client_info->client);
                if (rc != 0) {
                    InfoLog("%s: xfer_complete callback failed for client "
                            "socket %d, rc: %d", __func__, socket,
                            rc);
                    client_info->hangup(client_info->client);
                }
                client_socket_put(client_info);
                client_info = NULL; /* client_info may have been freed by now */
                return rc;
            }
            return 0;
        }
    }

    return 0;
}

static void client_socket_free(void *private)
{
    struct client_info *client_info = private;

    DbgLog(DL3, "%s: %p", __func__, client_info);

    if (client_info->free != NULL)
        client_info->free(client_info->client);
}

static int client_socket_receive(struct client_info *client_info,
                                 void *buffer, size_t size)
{
    if (client_info->socket < 0)
        return -ENOTCONN;

    client_info->xfer_state = XFER_RECEIVE;
    client_info->xfer_buffer = (char *)buffer;
    client_info->xfer_size = size;
    client_info->xfer_offset = 0;

    DbgLog(DL3, "%s: Start receive on client socket %d: buffer: %p size: %lu",
            __func__, client_info->socket, buffer, size);

    return client_socket_notify(EPOLLIN, client_info);
}


static int client_socket_send(struct client_info *client_info,
                              void *buffer, size_t size)
{
    if (client_info->socket < 0)
        return -ENOTCONN;

    client_info->xfer_state = XFER_SEND;
    client_info->xfer_buffer = (char *)buffer;
    client_info->xfer_size = size;
    client_info->xfer_offset = 0;

    DbgLog(DL3, "%s: Start send on client socket %d: buffer: %p size: %lu",
            __func__, client_info->socket, buffer, size);

    return client_socket_notify(EPOLLOUT, client_info);
}

static struct event_info *event_new(unsigned int payload_len,
                                    struct admin_conn_info *admin_conn)
{
    struct event_info *event;

    event = calloc(1, sizeof(struct event_info));
    if (event == NULL) {
        ErrLog("%s: Failed to allocate the event", __func__);
        return NULL;
    }

    event->event.version = EVENT_VERSION_1;
    event->event.payload_len = payload_len;
    if (payload_len > 0) {
        event->payload = malloc(payload_len);
        if (event->payload == NULL) {
            ErrLog("%s: Failed to allocate the event payload", __func__);
            free(event);
            return NULL;
        }
    }

    event->reply.version = EVENT_VERSION_1;

    if (admin_conn != NULL)
        admin_get(admin_conn);
    event->admin_ref = admin_conn;

    DbgLog(DL3, "%s: allocated event: %p", __func__, event);
    return event;
}

static void event_limit_underrun(void)
{
    struct admin_conn_info *conn;

    DbgLog(DL3, "%s: pending_events_count: %lu", __func__, pending_events_count);

#ifdef WITH_LIBUDEV
    /* Notify the udev monitor */
    udev_mon_notify(EPOLLIN, &udev_mon);
#endif

    /* Notify all admin connections */
    FOR_EACH_CONN_SAFE_BEGIN(admin_connections, conn) {
        admin_event_limit_underrun(conn);
    }
    FOR_EACH_CONN_SAFE_END(admin_connections, conn)
}

static void event_free(struct event_info *event)
{
    DbgLog(DL3, "%s: free event: %p", __func__, event);

    if (event->payload != NULL)
        free(event->payload);
    free(event);
}

static int event_add_to_pending_list(struct event_info *event)
{
    DL_NODE *list;

    list = dlist_add_as_last(pending_events, event);
    if (list == NULL) {
        ErrLog("%s: failed add event to list of pending events", __func__);
        return -ENOMEM;
    }
    pending_events = list;

    pending_events_count++;

    return 0;
}

static void event_remove_from_pending_list(struct event_info *event)
{
    DL_NODE *node;
    int trigger = 0;

    node = dlist_find(pending_events, event);
    if (node != NULL) {
        pending_events = dlist_remove_node(pending_events, node);

        if (pending_events_count >= MAX_PENDING_EVENTS)
            trigger = 1;

        if (pending_events_count > 0)
            pending_events_count--;

        if (trigger)
            event_limit_underrun();
    }
}

static int event_start_deliver(struct event_info *event)
{
    struct proc_conn_info *conn;
    int rc;

    DbgLog(DL3, "%s: event: %p", __func__, event);

    if (pending_events_count >= MAX_PENDING_EVENTS) {
        InfoLog("%s: Max pending events reached", __func__);
        return -ENOSPC;
    }

    /* Add event of the list of pending events */
    rc = event_add_to_pending_list(event);
    if (rc != 0)
        return rc;

    /*
     * Need to increment the event's ref count here, proc_deliver_event() may
     * already complete the event delivery for one process, which then would
     * free the event but it needs to be passed to other processes here, too.
     */
    event->proc_ref_count++;
    FOR_EACH_CONN_SAFE_BEGIN(proc_connections, conn) {
        rc = proc_deliver_event(conn, event);
        if (rc != 0)
            proc_hangup(conn);
    }
    FOR_EACH_CONN_SAFE_END(proc_connections, conn)
    event->proc_ref_count--;

    DbgLog(DL3, "%s: proc_ref_count: %lu", __func__, event->proc_ref_count);

    if (event->proc_ref_count == 0)
        event_delivered(event);

    return 0;
}

static void event_delivered(struct event_info *event)
{
    struct admin_conn_info *conn;
    int rc;

    DbgLog(DL3, "%s: event: %p", __func__, event);

    event_remove_from_pending_list(event);

    /* Notify owning admin connection (if available), free otherwise */
    if (event->admin_ref != NULL) {
        conn = event->admin_ref;
        admin_get(conn);
        rc = admin_event_delivered(conn, &event);
        if (rc != 0) {
            admin_hangup(conn);
            if (event != NULL)
                event_free(event);
        }
        admin_put(conn);
    } else {
        event_free(event);
    }
}

static int proc_new_conn(int socket, struct listener_info *listener)
{
    struct proc_conn_info *conn;
    struct event_info *event;
    DL_NODE *list, *node;
    struct ucred ucred;
    socklen_t  len;
    int rc = 0;

    UNUSED(listener);

    DbgLog(DL0, "%s: Accepted connection from process: socket: %d", __func__,
           socket);

    conn = calloc(1, sizeof(struct proc_conn_info));
    if (conn == NULL) {
        ErrLog("%s: Failed to to allocate memory for the process connection",
               __func__);
        return -ENOMEM;
        /* Caller will close socket */
    }

    DbgLog(DL3, "%s: process conn: %p", __func__, conn);

    len = sizeof(ucred);
    rc = getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
    if (rc != 0 || len != sizeof(ucred)) {
        rc = -errno;
        ErrLog("%s: failed get credentials of peer process: %s",
               strerror(-rc), __func__);
        free(conn);
        conn = NULL;
        goto out;
    }

    DbgLog(DL3, "%s: process pid: %u uid: %u gid: %u", __func__,
           ucred.pid, ucred.uid, ucred.gid);

    conn->client_cred.real_pid = ucred.pid;
    conn->client_cred.real_uid = ucred.uid;
    conn->client_cred.real_gid = ucred.gid;

    /* Add currently pending events to this connection */
    node = dlist_get_first(pending_events);
    while (node != NULL) {
        event = (struct event_info *)node->data;
        DbgLog(DL3, "%s: event: %p", __func__, event);

        list = dlist_add_as_last(conn->events, event);
        if (list == NULL) {
            ErrLog("%s: failed add event to list of process's pending events",
                   __func__);
            rc = -ENOMEM;
            goto out;
        }
        conn->events = list;

        event->proc_ref_count++;

        node = dlist_next(node);
    }

    conn->state = PROC_INITIAL_SEND;

    rc = client_socket_init(socket, proc_xfer_complete, proc_hangup, proc_free,
                            conn, &conn->client_info);
    if (rc != 0)
        goto out;

    /* Add it to the process connections list */
    list = dlist_add_as_first(proc_connections, conn);
    if (list == NULL) {
        rc = -ENOMEM;
        goto out;
    }
    proc_connections = list;

    proc_get(conn);
    rc = client_socket_send(&conn->client_info, &conn->client_cred,
                            sizeof(conn->client_cred));
    proc_put(conn);
    conn = NULL; /* conn may have been freed by now */

out:
    if (rc != 0 && conn != NULL) {
        proc_hangup(conn);
        rc = 0; /* Don't return an error, we have already handled it */
    }

    return rc;
}

static int proc_xfer_complete(void *client)
{
    struct proc_conn_info *conn = client;
    int rc;

    DbgLog(DL0, "%s: Xfer completed: process: %p socket: %d state: %d",
           __func__, conn, conn->client_info.socket, conn->state);

    /*
     * A non-zero return code returned by this function causes the caller to
     * call proc_hangup(). Thus, no need to call proc_hangup() ourselves.
     */

    switch (conn->state) {
    case PROC_INITIAL_SEND:
        conn->state = PROC_INITIAL_SEND2;
        rc = client_socket_send(&conn->client_info, &socketData,
                                sizeof(socketData));
        return rc;

    case PROC_INITIAL_SEND2:
        conn->state = PROC_WAIT_FOR_EVENT;
        rc = proc_start_deliver_event(conn);
        conn = NULL; /* conn may have been freed by now */
        return rc;

    case PROC_WAIT_FOR_EVENT:
        /* handled in proc_start_deliver_event */
        break;

    case PROC_SEND_EVENT:
        if (conn->event == NULL) {
            TraceLog("%s: No current event to handle", __func__);
            return -EINVAL;
        }

        if (conn->event->event.payload_len > 0) {
            conn->state = PROC_SEND_PAYLOAD;
            rc = client_socket_send(&conn->client_info, conn->event->payload,
                                    conn->event->event.payload_len);
            conn = NULL; /* conn may have been freed by now */
            return rc;
        }
        FALL_THROUGH;
        /* fall through */

    case PROC_SEND_PAYLOAD:
        if (conn->event == NULL) {
            TraceLog("%s: No current event to handle", __func__);
            return -EINVAL;
        }

        if (conn->event->event.flags & EVENT_FLAGS_REPLY_REQ) {
            conn->state = PROC_RECEIVE_REPLY;
            rc = client_socket_receive(&conn->client_info, &conn->reply,
                                       sizeof(conn->reply));
            conn = NULL; /* conn may have been freed by now */
            return rc;
        }
        FALL_THROUGH;
        /* fall through */

    case PROC_RECEIVE_REPLY:
        if (conn->event == NULL) {
            TraceLog("%s: No current event to handle", __func__);
            return -EINVAL;
        }

        if (conn->event->event.flags & EVENT_FLAGS_REPLY_REQ) {
            if (conn->reply.version != EVENT_VERSION_1) {
                InfoLog("%s: Reply has a wrong version: %u", __func__,
                        conn->reply.version);
                return -EINVAL;
            }

            /* Update reply counters in event */
            conn->event->reply.positive_replies += conn->reply.positive_replies;
            conn->event->reply.negative_replies += conn->reply.negative_replies;
            conn->event->reply.nothandled_replies +=
                                                conn->reply.nothandled_replies;
        }

        conn->state = PROC_WAIT_FOR_EVENT;

        rc = proc_event_delivered(conn, conn->event);
        conn = NULL; /* conn may have been freed by now */
        return rc;

    case PROC_HANGUP:
        break;
    }

    return 0;
}

static int proc_start_deliver_event(struct proc_conn_info *conn)
{
    DL_NODE *node;
    int rc;

    if (conn->state != PROC_WAIT_FOR_EVENT)
        return 0;

    node = dlist_get_first(conn->events);
    if (node == NULL)
        return 0;

    conn->event = node->data;
    memset(&conn->reply, 0, sizeof(conn->reply));

    DbgLog(DL3, "%s: process: %p event: %p", __func__, conn, conn->event);

    conn->state = PROC_SEND_EVENT;
    rc = client_socket_send(&conn->client_info, &conn->event->event,
                            sizeof(conn->event->event));
    conn = NULL; /* conn may have been freed by now */
    return rc;
}

static int proc_deliver_event(struct proc_conn_info *conn,
                              struct event_info *event)
{
    DL_NODE *list;
    int rc;

    DbgLog(DL3, "%s: process: %p event: %p", __func__, conn, event);

    if (conn->state == PROC_HANGUP)
        return 0;

    /* Add to process's event list and incr. reference count */
    list = dlist_add_as_last(conn->events, event);
    if (list == NULL) {
        ErrLog("%s: failed add event to list of process's pending events",
               __func__);
        return -ENOMEM;
    }
    conn->events = list;

    event->proc_ref_count++;

    rc = proc_start_deliver_event(conn);
    return rc;
}

static int proc_event_delivered(struct proc_conn_info *conn,
                                struct event_info *event)
{
    DL_NODE *node;
    int rc;

    DbgLog(DL3, "%s: process: %p event: %p", __func__, conn, event);

    conn->event = NULL;

    /* Remove from process's event list and decr. reference count */
    node = dlist_find(conn->events, event);
    if (node != NULL) {
        conn->events = dlist_remove_node(conn->events, node);
        event->proc_ref_count--;
    }

    DbgLog(DL3, "%s: proc_ref_count: %lu", __func__, event->proc_ref_count);

    if (event->proc_ref_count == 0)
        event_delivered(event);

    /* Deliver further pending events, if any */
    rc = proc_start_deliver_event(conn);
    conn = NULL; /* conn may have been freed by now */
    return rc;
}

static inline void proc_get(struct proc_conn_info *conn)
{
    client_socket_get(&conn->client_info);
}

static inline void proc_put(struct proc_conn_info *conn)
{
    client_socket_put(&conn->client_info);
}

static void proc_hangup(void *client)
{
    struct proc_conn_info *conn = client;
    struct event_info *event;
    DL_NODE *node;

    DbgLog(DL0, "%s: process: %p socket: %d state: %d", __func__, conn,
           conn->client_info.socket, conn->state);

    if (conn->state == PROC_HANGUP)
        return;
    conn->state = PROC_HANGUP;

    /* Unlink all pending events */
    while ((node = dlist_get_first(conn->events)) != NULL) {
        event = node->data;
        /* We did not handle this event */
        event->reply.nothandled_replies++;
        proc_event_delivered(conn, event);
    }

    client_socket_term(&conn->client_info);
    proc_put(conn);
}

static void proc_free(void *client)
{
    struct proc_conn_info *conn = client;
    DL_NODE *node;

    /* Remove it from the process connections list */
    node = dlist_find(proc_connections, conn);
    if (node != NULL) {
        proc_connections = dlist_remove_node(proc_connections, node);
        listener_client_hangup(&proc_listener);
    }

    DbgLog(DL0, "%s: process: %p", __func__, conn);
    free(conn);
}

static int admin_new_conn(int socket, struct listener_info *listener)
{
    struct admin_conn_info *conn;
    DL_NODE *list;
    int rc = 0;

    UNUSED(listener);

    DbgLog(DL0, "%s: Accepted connection from admin: socket: %d", __func__,
           socket);

    conn = calloc(1, sizeof(struct admin_conn_info));
    if (conn == NULL) {
        ErrLog("%s: Failed to to allocate memory for the admin connection",
               __func__);
        return -ENOMEM;
        /* Caller will close socket */
    }

    DbgLog(DL3, "%s: admin conn: %p", __func__, conn);

    conn->state = ADMIN_RECEIVE_EVENT;

    rc = client_socket_init(socket, admin_xfer_complete, admin_hangup,
                            admin_free, conn, &conn->client_info);
    if (rc != 0)
        goto out;

    conn->event = event_new(0, conn);
    if (conn->event == NULL) {
        ErrLog("%s: Failed to allocate a new event", __func__);
        rc = -ENOMEM;
        goto out;
    }

    /* Add it to the admin connections list */
    list = dlist_add_as_first(admin_connections, conn);
    if (list == NULL) {
        ErrLog("%s: Failed to add connection to list of admin connections",
               __func__);
        rc = -ENOMEM;
        goto out;
    }
    admin_connections = list;

    admin_get(conn);
    rc = client_socket_receive(&conn->client_info, &conn->event->event,
                               sizeof(conn->event->event));
    admin_put(conn);
    conn = NULL; /* conn may have been freed by now */

out:
    if (rc != 0 && conn != NULL) {
        admin_hangup(conn);
        rc = 0; /* Don't return an error, we have already handled it */
    }

    return rc;
}

static int admin_xfer_complete(void *client)
{
    struct admin_conn_info *conn = client;
    int rc;

    DbgLog(DL0, "%s: Xfer completed: admin: %p socket: %d state: %d",
           __func__, conn, conn->client_info.socket, conn->state);

    /*
     * A non-zero return code returned by this function causes the caller to
     * call admin_hangup(). Thus, no need to call admin_hangup() ourselves.
     */

    if (conn->event == NULL) {
        TraceLog("%s: No current event", __func__);
        return -EINVAL;
    }

    switch (conn->state) {
    case ADMIN_RECEIVE_EVENT:
        /* We have received the event from the admin */
        DbgLog(DL3, "%s: Event version:      %u", __func__,
               conn->event->event.version);
        DbgLog(DL3, "%s: Event type:         0x%08x", __func__,
               conn->event->event.type);
        DbgLog(DL3, "%s: Event flags:        0x%08x", __func__,
               conn->event->event.flags);
        DbgLog(DL3, "%s: Event token_type:   0x%08x", __func__,
               conn->event->event.token_type);
        DbgLog(DL3, "%s: Event token_name:   '%.32s'", __func__,
               conn->event->event.token_label);
        DbgLog(DL3, "%s: Event process_id:   %u", __func__,
               conn->event->event.process_id);
        DbgLog(DL3, "%s: Event payload_len:  %u", __func__,
               conn->event->event.payload_len);

        if (conn->event->event.version != EVENT_VERSION_1) {
            InfoLog("%s: Admin event has invalid version: %d", __func__,
                    conn->event->event.version);
            return -EINVAL;
        }
        if (conn->event->event.payload_len > EVENT_MAX_PAYLOAD_LENGTH) {
            InfoLog("%s: Admin event payload is too large: %u", __func__,
                    conn->event->event.payload_len);
            return -EMSGSIZE;
        }

        if (conn->event->event.payload_len > 0) {
            conn->event->payload = malloc(conn->event->event.payload_len);
            if (conn->event->payload == NULL) {
                ErrLog("%s: Failed to allocate the payload buffer", __func__);
                return -ENOMEM;
            }

            conn->state = ADMIN_RECEIVE_PAYLOAD;
            rc = client_socket_receive(&conn->client_info, conn->event->payload,
                                       conn->event->event.payload_len);
            conn = NULL; /* conn may have been freed by now */
            return rc;
        }
        FALL_THROUGH;
        /* fall through */

    case ADMIN_RECEIVE_PAYLOAD:
        /* We have received the payload (if any) from the admin */
        conn->state = ADMIN_EVENT_DELIVERED;
        rc = event_start_deliver(conn->event);
        if (rc != 0) {
            if (rc == -ENOSPC) {
                /* Event limit reached, delay */
                conn->state = ADMIN_WAIT_FOR_EVENT_LIMIT;
                return 0;
            }
            return rc;
        }
        break;

    case ADMIN_WAIT_FOR_EVENT_LIMIT:
        /* This state is handled in admin_event_limit_underrun() */
        break;

    case ADMIN_EVENT_DELIVERED:
        /* This state is handled in admin_event_delivered() */
        break;

    case ADMIN_SEND_REPLY:
        /* The reply has been sent to the admin */
        if (conn->event->admin_ref != NULL)
            admin_put(conn->event->admin_ref);
        conn->event->admin_ref = NULL;
        event_free(conn->event);

        conn->event = event_new(0, conn);
        if (conn->event == NULL) {
            ErrLog("%s: Failed to allocate a new event", __func__);
            return -ENOMEM;
        }

        conn->state = ADMIN_RECEIVE_EVENT;
        rc = client_socket_receive(&conn->client_info, &conn->event->event,
                                   sizeof(conn->event->event));
        conn = NULL; /* conn may have been freed by now */
        return rc;

    case ADMIN_HANGUP:
        break;
    }

    return 0;
}

static void admin_event_limit_underrun(struct admin_conn_info *conn)
{
    int rc;

    DbgLog(DL3, "%s: admin: %p state: %d", __func__, conn, conn->state);

    if (conn->state != ADMIN_WAIT_FOR_EVENT_LIMIT)
        return;

    conn->state = ADMIN_EVENT_DELIVERED;

    rc = event_start_deliver(conn->event);
    if (rc != 0) {
        if (rc == -ENOSPC) {
            /* Event limit reached, delay */
            conn->state = ADMIN_WAIT_FOR_EVENT_LIMIT;
            return;
        }
        admin_hangup(conn);
    }
}

static int admin_event_delivered(struct admin_conn_info *conn,
                                 struct event_info **event)
{
    int rc;

    DbgLog(DL3, "%s: admin: %p event: %p", __func__, conn, *event);

    /*
     * A non-zero return code returned by this function causes the caller to
     * call admin_hangup(). Thus, no need to call admin_hangup() ourselves.
     */

    if (conn->state != ADMIN_EVENT_DELIVERED) {
        TraceLog("%s: wrong state: %d", __func__, conn->state);
        return -EINVAL;
    }

    if ((*event)->event.flags & EVENT_FLAGS_REPLY_REQ) {
        if (conn->event != *event) {
            TraceLog("%s: event not the current event", __func__);
            return -EINVAL;
        }

        DbgLog(DL3, "%s: Reply version:      %u", __func__,
               (*event)->reply.version);
        DbgLog(DL3, "%s: Reply positive:     %u", __func__,
               (*event)->reply.positive_replies);
        DbgLog(DL3, "%s: Reply negative:     %u", __func__,
               (*event)->reply.negative_replies);
        DbgLog(DL3, "%s: Reply not-handled:  %u", __func__,
               (*event)->reply.nothandled_replies);

        conn->state = ADMIN_SEND_REPLY;
        rc = client_socket_send(&conn->client_info, &(*event)->reply,
                                sizeof((*event)->reply));
        return rc;
    }

    /* No reply required, free the event, and receive the next one */
    if ((*event)->admin_ref != NULL)
        admin_put((*event)->admin_ref);
    (*event)->admin_ref = NULL;
    event_free(*event);
    *event = NULL;

    conn->event = event_new(0, conn);
    if (conn->event == NULL) {
        ErrLog("%s: Failed to allocate a new event", __func__);
        return -ENOMEM;
    }

    conn->state = ADMIN_RECEIVE_EVENT;
    rc = client_socket_receive(&conn->client_info, &conn->event->event,
                               sizeof(conn->event->event));
    return rc;
}

static inline void admin_get(struct admin_conn_info *conn)
{
    client_socket_get(&conn->client_info);
}

static inline void admin_put(struct admin_conn_info *conn)
{
    client_socket_put(&conn->client_info);
}

static void admin_hangup(void *client)
{
    struct admin_conn_info *conn = client;

    DbgLog(DL0, "%s: admin: %p socket: %d state: %d", __func__, conn,
           conn->client_info.socket, conn->state);

    if (conn->state == ADMIN_HANGUP)
        return;
    conn->state = ADMIN_HANGUP;

    /* Unlink pending event (if any) */
    if (conn->event != NULL) {
        if (conn->event->admin_ref != NULL)
            admin_put(conn->event->admin_ref);
        conn->event->admin_ref = NULL;
        if (conn->event->proc_ref_count == 0) {
            event_remove_from_pending_list(conn->event);
            event_free(conn->event);
        }
        conn->event = NULL;
    }

    client_socket_term(&conn->client_info);
    admin_put(conn);
}

static void admin_free(void *client)
{
    struct admin_conn_info *conn = client;
    DL_NODE *node;

    /* Remove it from the admin connections list */
    node = dlist_find(admin_connections, conn);
    if (node != NULL) {
        admin_connections = dlist_remove_node(admin_connections, node);
        listener_client_hangup(&admin_listener);
    }

    DbgLog(DL0, "%s: admin: %p", __func__, conn);
    free(conn);
}

static int listener_socket_create(const char *file_path)
{
    struct sockaddr_un address;
    struct group *grp;
    int listener_socket, err;

    listener_socket = socket(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listener_socket < 0) {
        err = errno;
        ErrLog("%s: Failed to create listener socket, errno %d (%s).",
               __func__, err, strerror(err));
        return -1;
    }
    if (unlink(file_path) && errno != ENOENT) {
        err = errno;
        ErrLog("%s: Failed to unlink socket file, errno %d (%s).", __func__,
               err, strerror(err));
        goto error;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, file_path, sizeof(address.sun_path));
    address.sun_path[sizeof(address.sun_path) - 1] = '\0';

    if (bind(listener_socket,
             (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
        err = errno;
        ErrLog("%s: Failed to bind to socket, errno %d (%s).", __func__, err,
               strerror(err));
        goto error;
    }
    // make socket file part of the pkcs11 group, and write accessable
    // for that group
    grp = getgrnam(PKCS_GROUP);
    if (!grp) {
        ErrLog("%s: Group %s does not exist", __func__, PKCS_GROUP);
        goto error;
    }
    if (chown(file_path, -1, grp->gr_gid)) {
        err = errno;
        ErrLog("%s: Could not change file group on socket, errno %d (%s).",
               __func__, err, strerror(err));
        goto error;
    }
    if (chmod(file_path,
              S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP)) {
        err = errno;
        ErrLog("%s: Could not change file permissions on socket, errno %d (%s).",
                __func__, err, strerror(err));
        goto error;
    }

    if (listen(listener_socket, 20) != 0) {
        err = errno;
        ErrLog("%s: Failed to listen to socket, errno %d (%s).", __func__, err,
               strerror(err));
        goto error;
    }

    return listener_socket;

error:
    if (listener_socket >= 0)
        listener_socket_close(listener_socket, file_path);

    return -1;
}


static void listener_socket_close(int listener_socket, const char *file_path)
{
    close(listener_socket);
    unlink(file_path);
}



static int listener_notify(int events, void *private)
{
    struct listener_info *listener = private;
    struct sockaddr_un address;
    socklen_t address_length = sizeof(address);
    int client_socket, rc, err;

    if ((events & EPOLLIN) == 0)
        return 0;

    /* epoll is edge triggered. We must call accept until we get EWOULDBLOCK */
    while (listener->num_clients < listener->max_num_clients) {
        client_socket = accept(listener->socket, (struct sockaddr *) &address,
                               &address_length);
        if (client_socket < 0) {
            err = errno;
            if (err == EWOULDBLOCK)
                break;
            InfoLog("%s: Failed to accept connection on socket %d, errno %d (%s).",
                    __func__, listener->socket, err, strerror(err));
            return -err;
        }

        rc = listener->new_conn(client_socket, listener);
        if (rc != 0) {
            TraceLog("%s: new_conn callback failed for client socket %d, rc: %d",
                      __func__, client_socket, rc);
            close(client_socket);
            continue;
        }

        listener->num_clients++;
    }

    return 0;
}

static int listener_client_hangup(struct listener_info *listener)
{
    int rc, trigger = 0;

    if (listener->num_clients >= listener->max_num_clients)
        trigger = 1; /* We were at max clients, trigger accept now */

    if (listener->num_clients > 0)
        listener->num_clients--;

    if (trigger && listener->num_clients < listener->max_num_clients) {
        rc = listener_notify(EPOLLIN, listener);
        if (rc != 0)
            return rc;
    }

    return 0;
}

static int listener_create(const char *file_path,
                           struct listener_info *listener,
                           int (* new_conn)(int socket,
                                            struct listener_info *listener),
                           unsigned long max_num_clients)
{
    struct epoll_event evt;
    int rc, err;

    if (listener == NULL || new_conn == NULL)
        return FALSE;

    memset(listener, 0, sizeof(*listener));
    epoll_info_init(&listener->ep_info, listener_notify, NULL, listener);
    listener->file_path = file_path;
    listener->new_conn = new_conn;
    listener->max_num_clients = max_num_clients;

    listener->socket = listener_socket_create(file_path);
    if (listener->socket < 0)
        return FALSE;

    evt.events = EPOLLIN | EPOLLET;
    evt.data.ptr = &listener->ep_info;
    rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener->socket, &evt);
    if (rc != 0) {
        err = errno;
        TraceLog("%s: Failed add listener socket %d to epoll, errno %d (%s).",
                  __func__, listener->socket, err, strerror(err));
        return FALSE;
    }

    return TRUE;
}

static void listener_term(struct listener_info *listener)
{
    if (listener == NULL || listener->socket < 0)
        return;

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, listener->socket, NULL);
    listener_socket_close(listener->socket, listener->file_path);
}

#ifdef WITH_LIBUDEV

static int udev_mon_init(const char *subsystem, struct udev_mon *udev_mon)
{
    struct epoll_event evt;
    int rc, err;

    if (subsystem == NULL || udev_mon == NULL)
        return FALSE;

    udev_mon->delayed_event = 0;

    udev_mon->udev = udev_new();
    if (udev_mon->udev == NULL) {
        ErrLog("%s: udev_new failed", __func__);
        goto error;
    }

    udev_mon->mon = udev_monitor_new_from_netlink(udev_mon->udev, "udev");
    if (udev_mon->mon == NULL) {
        ErrLog("%s: udev_monitor_new_from_netlink failed", __func__);
        goto error;
    }

    /*
     * Try to increase the receive buffer size. This may fail if the required
     * privileges are not given. Ignore if it fails.
     */
    udev_monitor_set_receive_buffer_size(udev_mon->mon, UDEV_RECV_BUFFFER_SIZE);

    rc = udev_monitor_filter_add_match_subsystem_devtype(udev_mon->mon,
                                                         subsystem, NULL);
    if (rc != 0) {
        ErrLog("%s: udev_monitor_filter_add_match_subsystem_devtype failed: "
               "rc=%d", __func__, rc);
        goto error;
    }

    rc = udev_monitor_enable_receiving(udev_mon->mon);
    if (rc != 0) {
        ErrLog("%s: udev_monitor_enable_receiving failed: rc=%d", __func__, rc);
        goto error;
    }

    udev_mon->socket = udev_monitor_get_fd(udev_mon->mon);
    if (udev_mon->socket < 0) {
        ErrLog("%s: udev_monitor_get_fd failed", __func__);
        goto error;
    }

    epoll_info_init(&udev_mon->ep_info, udev_mon_notify, NULL, udev_mon);

    evt.events = EPOLLIN | EPOLLET;
    evt.data.ptr = &udev_mon->ep_info;
    rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udev_mon->socket, &evt);
    if (rc != 0) {
        err = errno;
        ErrLog("%s: Failed add udev_mon socket %d to epoll, errno %d (%s).",
                __func__, udev_mon->socket, err, strerror(err));
        goto error;
    }

    /* Epoll is edge triggered, thus try to receive once */
    rc = udev_mon_notify(EPOLLIN, udev_mon);
    if (rc != 0)
        goto error;

    return TRUE;

error:
    udev_mon_term(udev_mon);
    return FALSE;
}


static int udev_mon_handle_device(struct udev_mon *udev_mon,
                                  struct udev_device *dev)
{
    const char *action, *devname, *devpath, *devtype, *dev_type_prop;
    const char *config_prop = NULL, *online_prop = NULL;
    unsigned int card, domain, dev_type = 0;
    struct event_info *event;
    event_udev_apqn_data_t *apqn_data;
    int rc;

    UNUSED(udev_mon);

    action = udev_device_get_action(dev);
    devname = udev_device_get_sysname(dev);
    devpath = udev_device_get_devpath(dev);
    devtype = udev_device_get_devtype(dev);
    dev_type_prop = udev_device_get_property_value(dev, UDEV_PROPERTY_DEVTYPE);
    config_prop = udev_device_get_property_value(dev, UDEV_PROPERTY_CONFIG);
    online_prop = udev_device_get_property_value(dev, UDEV_PROPERTY_ONLINE);

    if (action == NULL || devname == NULL || devpath == NULL || devtype == NULL)
        return 0;

    DbgLog(DL3, "%s: Uevent: ACTION=%s DEVNAME=%s DEVPATH=%s DEVTYPE=%s "
           "DEV_TYPE=%s CONFIG:%s ONLINE=%s",
           __func__, action, devname, devpath, devtype,
           dev_type_prop != NULL ? dev_type_prop : "",
           config_prop != NULL ? config_prop : "",
           online_prop != NULL ? online_prop : "");

    /* We are only interested in bind, unbind, and change events ... */
    if (strcmp(action, UDEV_ACTION_BIND) != 0 &&
        strcmp(action, UDEV_ACTION_UNBIND) != 0 &&
        strcmp(action, UDEV_ACTION_CHANGE) != 0)
        return 0;

    /* ... for an APQN device */
    if (strcmp(devtype, UDEV_ACTION_DEVTYPE_APQN) != 0)
        return 0;

    if (sscanf(devname, "%x.%x", &card, &domain) != 2) {
        TraceLog("%s: failed to parse APQN from DEVNAME: %s", __func__, devname);
        return -EIO;
    }
    if (dev_type_prop != NULL) {
        if (sscanf(dev_type_prop, "%x", &dev_type) != 1) {
            TraceLog("%s: failed to parse DEV_TYPE: %s", __func__, dev_type_prop);
            return -EIO;
        }
    }

    event = event_new(sizeof(event_udev_apqn_data_t), NULL);
    if (event == NULL) {
        ErrLog("%s: failed to allocate an event", __func__);
        return -ENOMEM;
    }

    if (strcmp(udev_device_get_action(dev), UDEV_ACTION_CHANGE) == 0) {
        if (config_prop != NULL) {
            event->event.type = strcmp(config_prop, "1") == 0 ?
                    EVENT_TYPE_APQN_ADD : EVENT_TYPE_APQN_REMOVE;
        } else if (online_prop != NULL) {
            event->event.type = strcmp(online_prop, "1") == 0 ?
                    EVENT_TYPE_APQN_ADD : EVENT_TYPE_APQN_REMOVE;
        } else {
            event_free(event);
            return 0;
        }
    } else if (strcmp(udev_device_get_action(dev), UDEV_ACTION_BIND) == 0) {
        event->event.type = EVENT_TYPE_APQN_ADD;
    } else {
        event->event.type = EVENT_TYPE_APQN_REMOVE;
    }
    event->event.flags = EVENT_FLAGS_NONE;
    event->event.token_type = EVENT_TOK_TYPE_ALL;
    memset(event->event.token_label, ' ',
           sizeof(event->event.token_label));

    apqn_data = (event_udev_apqn_data_t *)event->payload;
    apqn_data->card = card;
    apqn_data->domain = domain;
    apqn_data->device_type = dev_type;

    DbgLog(DL3, "%s: Event version:      %u", __func__, event->event.version);
    DbgLog(DL3, "%s: Event type:         0x%08x", __func__, event->event.type);
    DbgLog(DL3, "%s: Event flags:        0x%08x", __func__, event->event.flags);
    DbgLog(DL3, "%s: Event token_type:   0x%08x", __func__,
           event->event.token_type);
    DbgLog(DL3, "%s: Event token_name:   '%.32s'", __func__,
           event->event.token_label);
    DbgLog(DL3, "%s: Event process_id:   %u", __func__, event->event.process_id);
    DbgLog(DL3, "%s: Event payload_len:  %u", __func__,
           event->event.payload_len);

    DbgLog(DL3, "%s: Payload: card:      %u", __func__, apqn_data->card);
    DbgLog(DL3, "%s: Payload: domain:    %u", __func__, apqn_data->domain);
    DbgLog(DL3, "%s: Payload: dev.type:  %u", __func__, apqn_data->device_type);

    rc = event_start_deliver(event);
    if (rc != 0) {
        if (rc == -ENOSPC) {
            /* Event limit reached, delay event delivery */
            udev_mon->delayed_event = event;
            return -ENOSPC;
        }
        event_free(event);
        return rc;
    }

    return 0;
}

static int udev_mon_notify(int events, void *private)
{
    struct udev_mon *udev_mon = private;
    struct udev_device *dev;
    struct event_info *event;
    int rc;

    DbgLog(DL3, "%s: Epoll event on udev_mon socket %d: events: 0x%x",
           __func__, udev_mon->socket, events);

    if (udev_mon->delayed_event != NULL) {
        /* Deliver delayed event first */
        event = udev_mon->delayed_event;
        udev_mon->delayed_event = NULL;

        rc = event_start_deliver(event);
        if (rc != 0) {
            if (rc == -ENOSPC) {
                /* Event limit reached, delay event delivery */
                udev_mon->delayed_event = event;
                return 0;
            }
            event_free(event);
            return rc;
        }
    }

    while (1) {
        dev = udev_monitor_receive_device(udev_mon->mon);
        if (dev == NULL)
            break; /* this is just like EWOULDBLOCK */

        rc = udev_mon_handle_device(udev_mon, dev);
        if (rc != 0)
            TraceLog("%s: udev_mon_handle_device failed, rc: %d", __func__, rc);

        udev_device_unref(dev);

        /* If event limit reached, stop receiving more events */
        if (rc == -ENOSPC)
            break;
    };

    return 0;
}

static void udev_mon_term(struct udev_mon *udev_mon)
{
    if (udev_mon == NULL)
        return;

    if (udev_mon->socket < 0)
        return;

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, udev_mon->socket, NULL);
    if (udev_mon->udev != NULL)
        udev_unref(udev_mon->udev);
    if (udev_mon->mon != NULL)
        udev_monitor_unref(udev_mon->mon);

    if (udev_mon->delayed_event != NULL)
        event_free(udev_mon->delayed_event);
}

#endif

int init_socket_data(Slot_Mgr_Socket_t *socketData)
{
    unsigned int processed = 0;

    PopulateCKInfo(&(socketData->ck_info));
    socketData->num_slots = NumberSlotsInDB;
    PopulateSlotInfo(socketData->slot_info, &processed);

    /* check that we read in correct amount of slots */
    if (processed != NumberSlotsInDB) {
        ErrLog("%s: Failed to populate slot info.", __func__);
        return FALSE;
    }

    return TRUE;
}

int socket_connection_handler(int timeout_secs)
{
    struct epoll_event events[MAX_EPOLL_EVENTS];
    int num_events, i, rc = 0, err;
    struct epoll_info *info;

    do {
        num_events = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS,
                                timeout_secs * 1000);
        if (num_events < 0) {
            err = errno;
            if (err == EINTR)
                continue;
            ErrLog("%s: epoll_wait failed, errno %d (%s).", __func__, err,
                   strerror(err));
            return FALSE;
        }

        /*
         * Inc ref count of all epoll_infos returned by epoll before handling
         * any of them via notify. The notify callback may hangup any of
         * the connections associated with the returned epoll_infos, and we
         * need to avoid them getting freed before we all handled them.
         */
        for (i = 0; i < num_events; i++)
            epoll_info_get(events[i].data.ptr);

        for (i = 0; i < num_events; i++) {
            info = events[i].data.ptr;
            if (info == NULL || info->notify == NULL)
                continue;

            rc = info->notify(events[i].events, info->private);
            if (rc != 0)
                TraceLog("%s: notify callback failed, rc: %d", __func__, rc);

            epoll_info_put(info);
        }
    } while (num_events > 0 && rc == 0); /* num_events = 0: timeout */

    return TRUE;
}

int init_socket_server(int event_support_disabled)
{
    int err;

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        err = errno;
        ErrLog("%s: Failed to open epoll socket, errno %d (%s).", __func__, err,
               strerror(err));
        return FALSE;
    }

    if (!listener_create(PROC_SOCKET_FILE_PATH, &proc_listener,
                         proc_new_conn, NUMBER_PROCESSES_ALLOWED)) {
        term_socket_server();
        return FALSE;
    }

    if (!event_support_disabled) {
        if (!listener_create(ADMIN_SOCKET_FILE_PATH, &admin_listener,
                             admin_new_conn, NUMBER_ADMINS_ALLOWED)) {
            term_socket_server();
            return FALSE;
        }

#ifdef WITH_LIBUDEV
        if (!udev_mon_init(UDEV_SUBSYSTEM_AP, &udev_mon)) {
            term_socket_server();
            return FALSE;
        }
#endif
    }

    DbgLog(DL0, "%s: Socket server started", __func__);

    return TRUE;
}

int term_socket_server(void)
{
    DL_NODE *node, *next;

#ifdef WITH_LIBUDEV
    udev_mon_term(&udev_mon);
#endif

    listener_term(&proc_listener);
    listener_term(&admin_listener);

    node = dlist_get_first(proc_connections);
    while (node != NULL) {
        next = dlist_next(node);
        proc_hangup(node->data);
        node = next;
    }
    dlist_purge(proc_connections);

    node = dlist_get_first(admin_connections);
    while (node != NULL) {
        next = dlist_next(node);
        admin_hangup(node->data);
        node = next;
    }
    dlist_purge(admin_connections);

    node = dlist_get_first(pending_events);
    while (node != NULL) {
        next = dlist_next(node);
        event_free((struct event_info *)node->data);
        node = next;
    }
    dlist_purge(pending_events);

    if (epoll_fd >= 0)
        close(epoll_fd);
    epoll_fd = -1;

    DbgLog(DL0, "%s: Socket server stopped", __func__);

    return TRUE;
}

#ifdef DEV

static void dump_listener(struct listener_info *listener)
{
    DbgLog(DL0, "    socket: %d", listener->socket);
    DbgLog(DL0, "    file_path: %s", listener->file_path);
    DbgLog(DL0, "    ep_info.ref_count: %lu", listener->ep_info.ref_count);
    DbgLog(DL0, "    num_clients: %lu", listener->num_clients);
    DbgLog(DL0, "    max_num_clients: %lu", listener->max_num_clients);
}

static void dump_event_msg(event_msg_t *event, int indent)
{
    DbgLog(DL0, "%*sevent version: %u", indent, "", event->version);
    DbgLog(DL0, "%*sevent type: %08x", indent, "", event->type);
    DbgLog(DL0, "%*sevent flags: %08x", indent, "", event->flags);
    DbgLog(DL0, "%*sevent token_type: %08x", indent, "", event->token_type);
    DbgLog(DL0, "%*sevent token_label: '%.32s'", indent, "", event->token_label);
    DbgLog(DL0, "%*sevent process_id: %lu", indent, "", event->process_id);
    DbgLog(DL0, "%*sevent payload_len: %u", indent, "", event->payload_len);
}

static void dump_event_reply(event_reply_t *reply, int indent)
{
    DbgLog(DL0, "%*sreply version: %u", indent, "", reply->version);
    DbgLog(DL0, "%*sreply positive_replies: %u", indent, "", reply->positive_replies);
    DbgLog(DL0, "%*sreply negative_replies: %u", indent, "", reply->negative_replies);
    DbgLog(DL0, "%*sreply nothandled_replies: %u", indent, "", reply->nothandled_replies);
}

static void dump_event_info(struct event_info *event, int indent)
{
    dump_event_msg(&event->event, indent);
    dump_event_reply(&event->reply, indent);
    DbgLog(DL0, "%*sproc_ref_count: %lu", indent, "", event->proc_ref_count);
    if (event->admin_ref != NULL)
        DbgLog(DL0, "%*sadmin_ref: %p", indent, "", event->admin_ref);
    else
        DbgLog(DL0, "%*sadmin_ref: None", indent, "");
}

static void dump_proc_conn(struct proc_conn_info *proc_conn)
{
    DL_NODE *node;
    unsigned long i;

    DbgLog(DL0, "      socket: %d", proc_conn->client_info.socket);
    DbgLog(DL0, "      state: %d", proc_conn->state);
    DbgLog(DL0, "      ref-count: %lu", proc_conn->client_info.ep_info.ref_count);
    DbgLog(DL0, "      xfer state: %d", proc_conn->client_info.xfer_state);
    DbgLog(DL0, "      xfer size: %d", proc_conn->client_info.xfer_size);
    DbgLog(DL0, "      xfer offset: %d", proc_conn->client_info.xfer_offset);
    DbgLog(DL0, "      pending events:");
    node = dlist_get_first(proc_conn->events);
    i = 1;
    while (node != NULL) {
        DbgLog(DL0, "        event %lu (%p):", i, node->data);
        dump_event_info(node->data, 10);
        node = dlist_next(node);
        i++;
    }
    if (proc_conn->event != NULL) {
        DbgLog(DL0, "      current event:");
        dump_event_info(proc_conn->event, 8);
        DbgLog(DL0, "      current reply:");
        dump_event_reply(&proc_conn->reply, 8);
    } else {
        DbgLog(DL0, "      current event: none");
    }
}

static void dump_admin_conn(struct admin_conn_info *admin_conn)
{
    DbgLog(DL0, "      socket: %d", admin_conn->client_info.socket);
    DbgLog(DL0, "      state: %d", admin_conn->state);
    DbgLog(DL0, "      ref-count: %lu", admin_conn->client_info.ep_info.ref_count);
    DbgLog(DL0, "      xfer state: %d", admin_conn->client_info.xfer_state);
    DbgLog(DL0, "      xfer size: %d", admin_conn->client_info.xfer_size);
    DbgLog(DL0, "      xfer offset: %d", admin_conn->client_info.xfer_offset);
    if (admin_conn->event != NULL) {
        DbgLog(DL0, "      current event (%p):", admin_conn->event);
        dump_event_info(admin_conn->event, 8);
    } else {
        DbgLog(DL0, "      current event: none");
    }
}

#ifdef WITH_LIBUDEV
void dump_udev_mon(struct udev_mon *udev_mon)
{
    DbgLog(DL0, "    socket: %d", udev_mon->socket);
    DbgLog(DL0, "    udev: %p", udev_mon->udev);
    DbgLog(DL0, "    mon: %p", udev_mon->mon);
    DbgLog(DL0, "    ep_info.ref_count: %lu", udev_mon->ep_info.ref_count);
    if (udev_mon->delayed_event != NULL) {
        DbgLog(DL0, "    delayed_event (%p):", udev_mon->delayed_event);
        dump_event_info(udev_mon->delayed_event, 6);
    } else {
        DbgLog(DL0, "    delayed_event: node");
    }
}
#endif

void dump_socket_handler(void)
{
    DL_NODE *node;
    unsigned long i;

    DbgLog(DL0, "%s: Dump of socket handler data:", __func__);
    DbgLog(DL0, "  epoll_fd: %d", epoll_fd);

    DbgLog(DL0, "  proc_listener (%p): ", &proc_listener);
    dump_listener(&proc_listener);

    DbgLog(DL0, "  proc_connections: ");
    node = dlist_get_first(proc_connections);
    i = 1;
    while (node != NULL) {
        DbgLog(DL0, "    proc_connection %lu (%p): ", i, node->data);
        dump_proc_conn(node->data);
        i++;
        node = dlist_next(node);
    }

    DbgLog(DL0, "  admin_listener (%p): ", &admin_listener);
    dump_listener(&admin_listener);

    DbgLog(DL0, "  admin_connections: ");
    node = dlist_get_first(admin_connections);
    i = 1;
    while (node != NULL) {
        DbgLog(DL0, "    admin_connection %lu (%p): ", i, node->data);
        dump_admin_conn(node->data);
        i++;
        node = dlist_next(node);
    }

#ifdef WITH_LIBUDEV
    DbgLog(DL0, "  udev_mon (%p): ", &udev_mon);
    dump_udev_mon(&udev_mon);
#endif

    DbgLog(DL0, "  pending events (%lu): ", pending_events_count);
    node = dlist_get_first(pending_events);
    i = 1;
    while (node != NULL) {
        DbgLog(DL0, "    event %lu (%p): ", i, node->data);
        dump_event_info(node->data, 6);
        i++;
        node = dlist_next(node);
    }
}
#endif
