/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdint.h>
#include <pkcs11types.h>
#include <limits.h>
#include <stdio.h>

#include "local_types.h"
#include "pkcs32.h"

#ifndef _EVENTS_H
#define _EVENTS_H

typedef struct {
    unsigned int version;       /* EVENT_VERSION_xxx */
    unsigned int type;          /* EVENT_TYPE_xxx */
    unsigned int flags;         /* EVENT_FLAGS_xxx */
    unsigned int token_type;    /* Destination token type: EVENT_TOK_TYPE_xxx */
    char token_label[member_size(CK_TOKEN_INFO_32, label)];
                                /* Label of destination token (or blanks) */
    pid_t process_id;           /* Process ID of destination process (or 0) */
    unsigned int payload_len;   /* Length of payload in bytes */
    /* Followed by payload_len bytes of payload (event specific) */
} __attribute__ ((__packed__)) event_msg_t;

typedef struct {
    unsigned int version;               /* EVENT_VERSION_xxx */
    unsigned int positive_replies;      /* Number of tokens that replied a */
    unsigned int negative_replies;      /* positive, or negative feedback, */
    unsigned int nothandled_replies;    /* or that did not handle the event. */
                                        /* Note: Only tokens matching the event
                                         * destination fields (pid, label,
                                         * token-type) are counted. */
} __attribute__ ((__packed__)) event_reply_t;

/* Event and reply versions */
#define EVENT_VERSION_1         1

/* Event classes (encoded into event type) */
#define EVENT_CLASS_MASK        0xffff0000
#define EVENT_CLASS_UDEV        0x00010000
#define EVENT_CLASS_ADMIN       0x00020000
#define EVENT_CLASS_MK_CHANGE   0x00040000

/* Event types */
#define EVENT_TYPE_APQN_ADD     EVENT_CLASS_UDEV + 0x00000001
#define EVENT_TYPE_APQN_REMOVE  EVENT_CLASS_UDEV + 0x00000002

#define EVENT_TYPE_MK_CHANGE_INITIATE_QUERY  EVENT_CLASS_MK_CHANGE + 0x00000001
#define EVENT_TYPE_MK_CHANGE_REENCIPHER      EVENT_CLASS_MK_CHANGE + 0x00000002
#define EVENT_TYPE_MK_CHANGE_FINALIZE_QUERY  EVENT_CLASS_MK_CHANGE + 0x00000003
#define EVENT_TYPE_MK_CHANGE_FINALIZE        EVENT_CLASS_MK_CHANGE + 0x00000004
#define EVENT_TYPE_MK_CHANGE_CANCEL_QUERY    EVENT_CLASS_MK_CHANGE + 0x00000005
#define EVENT_TYPE_MK_CHANGE_CANCEL          EVENT_CLASS_MK_CHANGE + 0x00000006

/* Event flags */
#define EVENT_FLAGS_NONE        0x00000000
#define EVENT_FLAGS_REPLY_REQ   0x00000001

/* Event token destination types */
#define EVENT_TOK_TYPE_ALL      0x00000000
#define EVENT_TOK_TYPE_CCA      0x00000001
#define EVENT_TOK_TYPE_EP11     0x00000002

/* Maximum event payload length 128k */
#define EVENT_MAX_PAYLOAD_LENGTH    (128 * 1024)

/* Event payload for EVENT_TYPE_APQN_ADD and EVENT_TYPE_APQN_REMOVE */
typedef struct {
    unsigned short card;
    unsigned short domain;
    unsigned int device_type;            /* from uevent DEV_TYPE property */
} __attribute__ ((__packed__)) event_udev_apqn_data_t;

/* AP device types */
#define AP_DEVICE_TYPE_CEX3A        8
#define AP_DEVICE_TYPE_CEX3C        9
#define AP_DEVICE_TYPE_CEX4         10
#define AP_DEVICE_TYPE_CEX5         11
#define AP_DEVICE_TYPE_CEX6         12
#define AP_DEVICE_TYPE_CEX7         13

/* Event payload for EVENT_TYPE_MK_CHANGE_xxx events */
typedef struct {
    char id[8];
    pid_t tool_pid;
    unsigned int flags;
    /* Followed by flattened struct hsm_mk_change_info */
} event_mk_change_data_t;

#define EVENT_MK_CHANGE_FLAGS_NONE            0x00000000
#define EVENT_MK_CHANGE_FLAGS_TOK_OBJS        0x00000001
#define EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL  0x00000002

#endif
