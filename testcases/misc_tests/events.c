/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event_client.h"
#include "regress.h"
#include "defs.h"

const char payload[20] = "12345678901234567890";

static inline void init_event_destination(struct event_destination *dest,
                                          unsigned int token_type,
                                          const char *label,
                                          pid_t process_id)
{
    size_t len;

    dest->token_type = token_type;
    dest->process_id = process_id;

    memset(dest->token_label, ' ', sizeof(dest->token_label));
    if (label != NULL) {
        len = strlen(label);
        memcpy(dest->token_label, label, len > sizeof(dest->token_label) ?
                                    sizeof(dest->token_label) : len);
    }
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int rc, fd = -1, ret = 1;
    struct event_destination dest;
    struct event_reply reply;

    UNUSED(argc);
    UNUSED(argv);

    rc = do_GetFunctionList();
    if (!rc) {
        testcase_error("do_getFunctionList(), rc=%s", p11_get_ckr(rc));
        return rc;
    }

    /*
     * Initialize Opencryptoki in this process, so that at least one
     * process is receiving the events.
     */
    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;
    funcs->C_Initialize(&cinit_args);

    testcase_setup();
    testcase_begin("Starting event tests");

    // Test fork before C_Initialize
    testcase_new_assertion();

    rc = send_event(-1, 0x12345, EVENT_FLAGS_NONE, 0, NULL, NULL, NULL);
    if (rc != 0) {
        testcase_fail("send_event (simple, one-shot) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    testcase_pass("send_event (simple, one-shot)");

    testcase_new_assertion();

    rc = send_event(-1, 0x12345, EVENT_FLAGS_NONE, sizeof(payload), payload,
                    NULL, NULL);
    if (rc != 0) {
        testcase_fail("send_event (payload, one-shot) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    testcase_pass("send_event (payload, one-shot)");

    testcase_new_assertion();

    init_event_destination(&dest, EVENT_TOK_TYPE_CCA, NULL, 0);

    rc = send_event(-1, 0x12345, EVENT_FLAGS_NONE, 0, NULL, &dest, NULL);
    if (rc != 0) {
        testcase_fail("send_event (token-type, one-shot) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    testcase_pass("send_event (token-type, one-shot)");

    testcase_new_assertion();

    init_event_destination(&dest, EVENT_TOK_TYPE_ALL, "cca", 0);

    rc = send_event(-1, 0x12345, EVENT_FLAGS_NONE, 0, NULL, &dest, NULL);
    if (rc != 0) {
        testcase_fail("send_event (token-label, one-shot) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    testcase_pass("send_event (token-label, one-shot)");

    testcase_new_assertion();

    init_event_destination(&dest, EVENT_TOK_TYPE_ALL, NULL, 12345);

    rc = send_event(-1, 0x12345, EVENT_FLAGS_NONE, 0, NULL, &dest, NULL);
    if (rc != 0) {
        testcase_fail("send_event (pid, one-shot) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    testcase_pass("send_event (pid, one-shot)");

    testcase_new_assertion();

    memset(&reply, 0, sizeof(reply));

    rc = send_event(-1, 0x12345, EVENT_FLAGS_REPLY_REQ, 0, NULL, NULL, &reply);
    if (rc != 0) {
        testcase_fail("send_event (reply, one-shot) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    printf("Reply: positive_replies:    %lu\n", reply.positive_replies);
    printf("       negative_replies:    %lu\n", reply.negative_replies);
    printf("       nothandled_replies:  %lu\n", reply.nothandled_replies);
    if (reply.positive_replies + reply.negative_replies +
            reply.nothandled_replies == 0) {
        testcase_fail("send_event (reply, one-shot) replies all zero");
        goto out;
    }
    testcase_pass("send_event (reply, one-shot)");

    testcase_new_assertion();

    fd = init_event_client();
    if (fd < 0) {
        testcase_fail("init_event_client rc = %d (%s)", fd, strerror(-fd));
        goto out;
    }
    testcase_pass("init_event_client()");

    testcase_new_assertion();

    rc = send_event(fd, 0x12345, EVENT_FLAGS_NONE, 0, NULL, NULL, NULL);
    if (rc != 0) {
        testcase_fail("send_event (simple) rc = %d (%s)", rc, strerror(-rc));
        goto out;
    }
    testcase_pass("send_event (simple)");

    testcase_new_assertion();

    rc = send_event(fd, 0x12345, EVENT_FLAGS_NONE, sizeof(payload), payload,
                    NULL, NULL);
    if (rc != 0) {
        testcase_fail("send_event (payload) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    testcase_pass("send_event (payload)");

    testcase_new_assertion();

    memset(&reply, 0, sizeof(reply));

    rc = send_event(-1, 0x12345, EVENT_FLAGS_REPLY_REQ, 0, NULL, NULL, &reply);
    if (rc != 0) {
        testcase_fail("send_event (reply) rc = %d (%s)", rc,
                      strerror(-rc));
        goto out;
    }
    printf("Reply: positive_replies:    %lu\n", reply.positive_replies);
    printf("       negative_replies:    %lu\n", reply.negative_replies);
    printf("       nothandled_replies:  %lu\n", reply.nothandled_replies);
    if (reply.positive_replies + reply.negative_replies +
            reply.nothandled_replies == 0) {
        testcase_fail("send_event (reply) replies all zero");
        goto out;
    }
    testcase_pass("send_event (reply)");

    term_event_client(fd);
    fd = -1;

    ret = 0;

out:
    if (fd >= 0)
        term_event_client(fd);

    funcs->C_Finalize(NULL);

    testcase_print_result();

    return testcase_return(ret);
}
