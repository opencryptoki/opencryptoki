/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */


#ifndef _EVENT_CLIENT_H_
#define _EVENT_CLIENT_H_

#include "events.h"

struct event_destination {
    unsigned int token_type;    /* Destination token type: EVENT_TOK_TYPE_xxx */
    char token_label[32];       /* Label of destination token (or blanks) */
    pid_t process_id;           /* Process ID of destination process (or 0) */
};

struct event_reply {
    unsigned long positive_replies;
    unsigned long negative_replies;
    unsigned long nothandled_replies;
};

int init_event_client();

int send_event(int fd, unsigned int type, unsigned int flags,
               unsigned int payload_len, const char *payload,
               const struct event_destination *destination,
               struct event_reply *reply);

void term_event_client(int fd);

#endif
