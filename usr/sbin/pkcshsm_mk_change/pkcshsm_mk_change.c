/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * pkcshsm_mk_change - A tool to manage and control the re-enciphering of
 * secure keys for a concurrent HSM master key change.
 */

#include "platform.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>

#include "pkcs11types.h"
#include "p11util.h"
#include "event_client.h"
#include "pkcs_utils.h"
#include "hsm_mk_change.h"
#include "pin_prompt.h"

#if defined(_AIX)
    #include <libgen.h>
    #define ELIBACC EINVAL
    const char *__progname = "pkcshsm_mk_change";
#endif

#define CMD_REENCIPHER  1
#define CMD_FINALIZE    2
#define CMD_CANCEL      3
#define CMD_LIST        4

#define CCA_MKVP_LENGTH             8
#define EP11_WKVP_LENGTH            16

#define UNUSED(var)            ((void)(var))

pkcs_trace_level_t trace_level = TRACE_LEVEL_NONE;

static void *dll = NULL;
static CK_FUNCTION_LIST *func_list = NULL;
static int event_fd = -1;
static struct apqn *apqns = NULL;
static unsigned int num_apqns = 0;
static const char *id = NULL;
static unsigned char ep11_wkvp[EP11_WKVP_LENGTH] = { 0 };
static bool ep11_wkvp_set = false;
static unsigned char cca_sym_mkvp[CCA_MKVP_LENGTH] = { 0 };
static bool cca_sym_mkvp_set = false;
static unsigned char cca_asym_mkvp[CCA_MKVP_LENGTH] = { 0 };
static bool cca_asym_mkvp_set = false;
static unsigned char cca_aes_mkvp[CCA_MKVP_LENGTH] = { 0 };
static bool cca_aes_mkvp_set = false;
static unsigned char cca_apka_mkvp[CCA_MKVP_LENGTH] = { 0 };
static bool cca_apka_mkvp_set = false;

struct token_info {
    CK_SLOT_ID id;
    bool present;
    CK_TOKEN_INFO info;
    bool affected;
    CK_SESSION_HANDLE session;
};

CK_ULONG num_affected_slots = 0;
CK_SLOT_ID_PTR affected_slots = NULL;
static unsigned int num_tokens = 0;
static struct token_info *tokens = NULL;

struct hsm_mk_change_op op;
struct hsm_mkvp mkvps[HSM_MK_TYPE_MAX];

static void usage(char *progname)
{
    printf("Usage: %s COMMAND [OPTIONS]\n\n", progname);
    printf("Manage and control the re-enciphering of secure keys for a concurrent\n"
           "HSM master key change.\n\n");
    printf("COMMAND:\n");
    printf(" reencipher               initiate a master key change operation for the\n"
           "                          specified APQNs and master key types and re-encipher\n"
           "                          all session and token key objects of the affected\n"
           "                          tokens.\n");
    printf(" finalize                 finalize a master key change operation when the\n"
           "                          new master key has been activated on the APQNs.\n");
    printf(" cancel                   cancel a master key change operation.\n");
    printf(" list                     list currently active master key change operations.\n");
    printf("\nOPTIONS:\n");
    printf(" -a, --apqns APQNS        specifies a comma separated list of APQNs for\n"
           "                          which a master key change is to be performed.\n"
#if defined(_AIX)
           "                          MUST be '0.0' on AIX for operation to succeed.\n"
#endif
           "                          Only valid with the 'reencipher' command.\n");
    printf(" -e, --ep11-wkvp WKVP     specifies the EP11 wrapping key verification pattern\n"
           "                          of the new, to be set EP11 wrapping key as a\n"
           "                          16 bytes hex string.\n"
           "                          Only valid with the 'reencipher' command.\n");
    printf(" -s, --cca-sym-mkvp MKVP  specifies the CCA master key verification pattern\n"
           "                          of the new, to be set CCA SYM master key as a\n"
           "                          8 bytes hex string.\n"
           "                          Only valid with the 'reencipher' command.\n");
    printf(" -S, --cca-asym-mkvp MKVP specifies the CCA master key verification pattern\n"
           "                          of the new, to be set CCA ASYM master key as a\n"
           "                          8 bytes hex string.\n"
           "                          Only valid with the 'reencipher' command.\n");
    printf(" -A, --cca-aes-mkvp MKVP  specifies the CCA master key verification pattern\n"
           "                          of the new, to be set CCA AES master key as a\n"
           "                          8 bytes hex string.\n"
           "                          Only valid with the 'reencipher' command.\n");
    printf(" -p, --cca-apka-mkvp MKVP specifies the CCA master key verification pattern\n"
           "                          of the new, to be set CCA APKA master key as a\n"
           "                          8 bytes hex string.\n"
           "                          Only valid with the 'reencipher' command.\n");
    printf(" -i, --id OPERATION-ID    specifies the ID of the master key change operation\n"
           "                          to finalize, cancel, or list.\n");
    printf(" -v, --verbose LEVEL      set verbose level (optional):\n");
    printf("                          none (default), error, warn, info, devel, debug\n");
    printf(" -h, --help               display help information.\n");

    return;
}

static int parse_apqn(char *apqn)
{
    unsigned int card, domain, num;
    struct apqn *tmp;

    TRACE_DEVEL("APQN: '%s'\n", apqn);

    if (sscanf(apqn, "%x.%x%n", &card, &domain, (int *)&num) != 2 ||
        num != strlen(apqn) || card > 0xff || domain > 0xFFFF) {
        warnx("Invalid APQN specification: %s", apqn);
        return EINVAL;
    }

    tmp = realloc(apqns, (num_apqns + 1) * sizeof(struct apqn));
    if (tmp == NULL) {
        warnx("Failed to allocate memory for APQN list");
        return ENOMEM;
    }

    tmp[num_apqns].card = card;
    tmp[num_apqns].domain = domain;

    num_apqns++;
    apqns = tmp;

    return 0;
}

static int parse_apqns(char *apqns)
{
    char *saveptr, *tok;
    int rc = 0;

    TRACE_DEVEL("APQNs: '%s'\n", apqns);

    tok = strtok_r(apqns, ", ", &saveptr);
    while(tok != NULL) {
        rc = parse_apqn(tok);
        if (rc != 0)
            return rc;

        tok = strtok_r(NULL, ", ", &saveptr);
    }

    if (apqns == NULL || num_apqns == 0) {
        warnx("No APQNs specified with option -a/--apqns");
        return EINVAL;
    }

    return 0;
}

static int parse_mkvp(char *mkvp_str, size_t min_size, unsigned char *mkvp,
                      bool *set, const char *option)
{
    unsigned int i, val;

    TRACE_DEVEL("MKVP: '%s'\n", mkvp_str);

    if (strncasecmp(mkvp_str, "0x", 2) == 0)
        mkvp_str += 2;

    if (strlen(mkvp_str) < min_size * 2) {
        warnx("option %s must specify at least %zu bytes", option, min_size);
        return EINVAL;
    }

    for (i = 0; i < min_size; i++) {
        if (sscanf(mkvp_str + (i * 2), "%02x", &val) != 1) {
            warnx("option %s does not specify a valid hex string", option);
            return EINVAL;
        }
        mkvp[i] = val;
    }

    if (strlen(mkvp_str) > min_size * 2)
        warnx("option %s specifies more than %zu bytes, remaining bytes are ignored",
              option, min_size);

    *set = true;
    return 0;
}

static const char *get_mk_type_string(enum hsm_mk_type mk_type)
{
    switch (mk_type) {
    case HSM_MK_TYPE_EP11:
        return "EP11 WK";
    case HSM_MK_TYPE_CCA_SYM:
        return"CCA SYM";
    case HSM_MK_TYPE_CCA_ASYM:
        return"CCA ASYM";
    case HSM_MK_TYPE_CCA_AES:
        return "CCA_AES";
    case HSM_MK_TYPE_CCA_APKA:
        return "CCA APKA";
    default:
        return "UNKNOWN";
    }
}

static CK_RV check_intersecting_ops_cb(struct hsm_mk_change_op *other_op,
                                       void *private)
{
    unsigned int i, k;
    bool *error = private;

    for (i = 0; i < op.info.num_apqns; i++) {
        if (hsm_mk_change_apqns_find(other_op->info.apqns,
                                     other_op->info.num_apqns,
                                     op.info.apqns[i].card,
                                     op.info.apqns[i].domain)) {
            /* Same APQN found */
            for (k = 0; k < op.info.num_mkvps; k++) {
                if (hsm_mk_change_mkvps_find(other_op->info.mkvps,
                                             other_op->info.num_mkvps,
                                             op.info.mkvps[k].type, 0)) {
                    /* Same MKVP type */
                    warnx("Operation '%s' also affects APQN %02X.%04X and MK type '%s'",
                          other_op->id, apqns[i].card, apqns[i].domain,
                          get_mk_type_string(op.info.mkvps[k].type));
                    *error = true;
                }
            }
        }
    }

    return CKR_OK;
}

static int check_intersecting_ops(void)
{
    CK_RV rv;
    bool error = false;

    rv = hsm_mk_change_op_iterate(check_intersecting_ops_cb, &error);
    if (rv != CKR_OK) {
        warnx("Failed to iterate over active operations");
        return EIO;
    }

    if (error != false) {
        warnx("Intersecting master key operations are active, aborting");
        return EALREADY;
    }

    return 0;
}

static int check_tokens_present(void)
{
    CK_ULONG i;
    bool all_present = true;
    ssize_t num_chars;
    char *buff = NULL;
    size_t buflen = 0;

    for (i = 0; i < num_tokens; i++)
        all_present &= tokens[i].present;

    if (all_present)
        return 0;

    printf("WARNING: The following slots have no token present:\n");
    for (i = 0; i < num_tokens; i++) {
        if (tokens[i].present == false)
            printf("  Slot %lu\n", tokens[i].id);
    }
    printf("ATTENTION: If you start a concurrent master key change operation while not\n"
           "all expected tokens are present, the key objects of those tokens may be lost,\n"
           "if the token would be affected by the master key change.\n");
    printf("Continue [y/N]? ");
    fflush(stdout);
    num_chars = getline(&buff, &buflen, stdin);
    if (num_chars < 0 || strncmp(buff, "y", 1) != 0) {
        printf("Aborted by user.\n");
        free(buff);
        return ECANCELED;
    }
    free(buff);

    return 0;
}

static int create_mk_change_op(void)
{
    CK_RV rv;

    rv = hsm_mk_change_lock(true);
    if (rv != CKR_OK) {
        warnx("Failed to obtain lock");
        return EIO;
    }

    rv = hsm_mk_change_op_create(&op);
    if (rv != CKR_OK) {
        warnx("Failed to create MK change operation file");
        hsm_mk_change_unlock();
        return EIO;
    }

    rv = hsm_mk_change_unlock();
    if (rv != CKR_OK) {
        warnx("Failed to release lock");
        hsm_mk_change_op_remove(op.id);
        return EIO;
    }

    return 0;
}

static int save_mk_change_op(void)
{
    CK_RV rv;

    rv = hsm_mk_change_lock(true);
    if (rv != CKR_OK) {
        warnx("Failed to obtain lock");
        return EIO;
    }

    rv = hsm_mk_change_op_save(&op);
    if (rv != CKR_OK) {
        warnx("Failed to save MK change operation file");
        hsm_mk_change_unlock();
        return EIO;
    }

    rv = hsm_mk_change_unlock();
    if (rv != CKR_OK) {
        warnx("Failed to release lock");
        return EIO;
    }

    return 0;
}

static int load_mk_change_op(const char *id)
{
    CK_RV rv;

    rv = hsm_mk_change_lock(false);
    if (rv != CKR_OK) {
        warnx("Failed to obtain lock");
        return EIO;
    }

    rv = hsm_mk_change_op_load(id, &op);
    if (rv != 0) {
        warnx("Failed to load MK change operation file");
        hsm_mk_change_unlock();
        return EIO;
    }

    rv = hsm_mk_change_unlock();
    if (rv != 0) {
        warnx("Failed to release lock");
        return EIO;
    }

    return 0;
}

static int remove_mk_change_op(void)
{
    CK_RV rv;

    rv = hsm_mk_change_lock(true);
    if (rv != CKR_OK) {
        warnx("Failed to obtain lock");
        return EIO;
    }

    rv = hsm_mk_change_op_remove(op.id);
    if (rv != CKR_OK) {
        warnx("Failed to remove MK change operation file(s)");
        hsm_mk_change_unlock();
        return EIO;
    }

    rv = hsm_mk_change_unlock();
    if (rv != CKR_OK) {
        warnx("Failed to release lock");
        return EIO;
    }

    return 0;
}

static int build_event_payload(unsigned char **payload, size_t *payload_len)
{
    event_mk_change_data_t *hdr;
    size_t info_len = 0;
    CK_RV rv;

    rv = hsm_mk_change_info_flatten(&op.info, NULL, &info_len);
    if (rv != CKR_OK) {
        warnx("Failed to query size of event payload buffer");
        return EIO;
    }

    *payload_len = sizeof(*hdr) + info_len;
    *payload = calloc(1, *payload_len);
    if (*payload == NULL) {
        warnx("Failed to allocate event payload buffer");
        *payload_len = 0;
        return ENOMEM;
    }

    hdr = (event_mk_change_data_t *)*payload;
    strncpy(hdr->id, op.id, sizeof(hdr->id));
    hdr->tool_pid = getpid();
    hdr->flags = 0;

    rv = hsm_mk_change_info_flatten(&op.info, *payload + sizeof(*hdr),
                                    &info_len);
    if (rv != CKR_OK) {
        warnx("Failed to flatten operation info");
        free(*payload);
        *payload = NULL;
        *payload_len = 0;
        return EIO;
    }

    return 0;
}

static int send_query_event(unsigned int event, const char *msg_cmd,
                            CK_ULONG *num_affected_slots)
{
    size_t payload_len;
    unsigned char *payload = NULL;
    struct event_destination dest;
    struct event_reply reply;
    CK_ULONG i, num_errors = 0;
    int rc = 0;

    TRACE_DEVEL("Event: 0x%08x\n", event);

    *num_affected_slots = 0;

    rc = build_event_payload(&payload, &payload_len);
    if (rc != 0)
        return rc;

    for (i = 0; i < num_tokens; i++) {
        if (tokens[i].present == false)
            continue;

        TRACE_DEVEL("Slot %lu\n", tokens[i].id);

        dest.process_id = getpid(); /* Send to current process only */
        dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
        memcpy(dest.token_label, tokens[i].info.label,
               sizeof(dest.token_label)); /* selected token only */

        memset(&reply, 0, sizeof(reply));

        rc = send_event(event_fd, event, EVENT_FLAGS_REPLY_REQ,
                        payload_len, (char *)payload, &dest, &reply);
        if (rc != 0) {
            warnx("Failed to send event: %d", rc);
            rc = EIO;
            goto out;
        }

        TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
        TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
        TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

        if (reply.positive_replies > 1 ||
            reply.negative_replies > 1 ||
            reply.nothandled_replies > 1) {
            warnx("More than one token responded to the query event for slot %lu",
                  tokens[i].id);
            warnx("Possibly multiple tokens use the same label?");
            rc = EIO;
            goto out;
        }

        if (reply.negative_replies == 1) {
            warnx("Token in slot %lu is unable to perform the %s.",
                  tokens[i].id, msg_cmd);
            num_errors++;
        }

        if (reply.positive_replies == 1) {
            tokens[i].affected = true;
            (*num_affected_slots)++;
        }
    }

    TRACE_DEVEL("num_errors: %lu\n", num_errors);

    if (num_errors > 0) {
        warnx("At least one token is unable to perform the %s, aborting.",
              msg_cmd);
        rc = EINVAL;
        goto out;
    }

    TRACE_DEVEL("num_affected_slots: %lu\n", *num_affected_slots);

out:
    free(payload);

    return rc;
}

static int query_tokens_initiate_mk_change(void)
{
    CK_ULONG i, k;
    int rc;

    rc = send_query_event(EVENT_TYPE_MK_CHANGE_INITIATE_QUERY,
                          "master key change", &num_affected_slots);
    if (rc != 0)
        return rc;

    if (num_affected_slots == 0) {
        warnx("No token is affected by this master key change, aborting");
        return ECANCELED;
    }

    affected_slots = calloc(num_affected_slots, sizeof(CK_SLOT_ID));
    if (affected_slots == NULL) {
        warnx("Failed to allocate list of affected slots");
        return ENOMEM;
    }

    for (i = 0, k = 0; i < num_tokens && k < num_affected_slots; i++) {
        if (tokens[i].affected == true) {
            affected_slots[k] = tokens[i].id;
            k++;
        }
    }

    printf("The following tokens are affected by this master key change:\n");
    for (i = 0; i < num_tokens; i++) {
        if (tokens[i].affected == true)
            printf("  Slot %lu: Label: %.32s\n", tokens[i].id, tokens[i].info.label);
    }

    return 0;
}

static int login_tokens(void)
{
    char msg[200];
    const char *userpin = NULL;
    char *buf_user = NULL;
    CK_ULONG i;
    int rc = 0;
    CK_RV rv;

    for (i = 0; i < num_tokens; i++) {
        if (tokens[i].affected == false)
            continue;

        TRACE_DEVEL("Slot %lu\n", tokens[i].id);

        snprintf(msg, sizeof(msg), "Enter the USER PIN for slot %lu: ",
                 tokens[i].id);
get_pin:
        userpin = pin_prompt(&buf_user, msg);
        if (userpin == NULL) {
            warnx("Aborted by user.");
            rc = ECANCELED;
            goto out;
        }

        if (strlen(userpin) == 0) {
            warnx("Empty pin entered, try again.");
            pin_free(&buf_user);
            goto get_pin;
        }

        rv = func_list->C_OpenSession(tokens[i].id,
                                      CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                      NULL, NULL, &tokens[i].session);
        if (rv != CKR_OK) {
            warnx("Error opening an R/W session with slot %lu: 0x%lX (%s)",
                  tokens[i].id, rv, p11_get_ckr(rv));
            rc = EIO;
            goto out;
        }

        rv = func_list->C_Login(tokens[i].session, CKU_USER,
                                (CK_CHAR_PTR)userpin, strlen(userpin));
        if (rv != CKR_OK) {
            warnx("Error logging in for slot %lu: 0x%lX (%s)",
                  tokens[i].id, rv, p11_get_ckr(rv));
            rc = EINVAL;
            goto out;
        }

        pin_free(&buf_user);
    }

out:
    pin_free(&buf_user);
    return rc;
}

static void logout_tokens(void)
{
    CK_ULONG i;

    for (i = 0; i < num_tokens; i++) {
        if (tokens[i].affected == false)
            continue;
        if (tokens[i].session == CK_INVALID_HANDLE)
            continue;

        func_list->C_Logout(tokens[i].session);
        func_list->C_CloseAllSessions(tokens[i].id);
    }
}

static int reencipher_tokens(void)
{
    size_t payload_len;
    unsigned char *payload = NULL;
    event_mk_change_data_t *hdr;
    struct event_destination dest;
    struct event_reply reply;
    int rc = 0;

    rc = build_event_payload(&payload, &payload_len);
    if (rc != 0)
        return rc;

    /*
     * Let all tokens re-encipher their session objects.
     * This activates the MK change operation for the processes.
     * New token objects will be re-enciphered by the processes, existing
     * token objects are not yet re-enciphered. Since the new WK is not yet
     * set/activated on the APQNs at that point in time, this does not matter.
     */
    hdr = (event_mk_change_data_t *)payload;
    hdr->flags = EVENT_MK_CHANGE_FLAGS_NONE;

    dest.process_id = 0;
    dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
    memset(dest.token_label, ' ', sizeof(dest.token_label));

    memset(&reply, 0, sizeof(reply));

    rc = send_event(event_fd, EVENT_TYPE_MK_CHANGE_REENCIPHER,
                    EVENT_FLAGS_REPLY_REQ, payload_len, (char *)payload,
                    &dest, &reply);
    if (rc != 0) {
        warnx("Failed to send event: %d", rc);
        rc = EIO;
        goto out;
    }

    TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
    TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
    TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

    if (reply.negative_replies != 0 || reply.positive_replies == 0)
        goto cancel;

    /*
     * Let the tool process re-encipher the token objects.
     * After that, all objects are re-enciphered.
     */
    hdr->flags = EVENT_MK_CHANGE_FLAGS_TOK_OBJS;

    dest.process_id = getpid(); /* Send to current process only */
    dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
    memset(dest.token_label, ' ', sizeof(dest.token_label));

    memset(&reply, 0, sizeof(reply));

    rc = send_event(event_fd, EVENT_TYPE_MK_CHANGE_REENCIPHER,
                    EVENT_FLAGS_REPLY_REQ, payload_len, (char *)payload,
                    &dest, &reply);
    if (rc != 0) {
        warnx("Failed to send event: %d", rc);
        rc = EIO;
        goto out;
    }

    TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
    TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
    TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

    if (reply.negative_replies != 0 || reply.positive_replies == 0)
        goto cancel;

out:
    free(payload);

    return rc;

cancel:
    warnx("At least one token failed to perform the key re-encryption.");
    warnx("Check the syslog for details about the errors reported by the tokens.");

    /* Cancel the MK change operation */
    op.state = HSM_MK_CH_STATE_CANCELING;

    rc = save_mk_change_op();
    if (rc != 0)
        goto out;

    /* Let all tokens cancel their session object re-enciphering */
    hdr->flags = EVENT_MK_CHANGE_FLAGS_NONE;

    dest.process_id = 0;
    dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
    memset(dest.token_label, ' ', sizeof(dest.token_label));

    rc = send_event(event_fd, EVENT_TYPE_MK_CHANGE_CANCEL,
                    EVENT_FLAGS_REPLY_REQ, payload_len, (char *)payload,
                    &dest, &reply);
    if (rc != 0) {
        warnx("Failed to send event: %d", rc);
        rc = EIO;
        goto out;
    }

    TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
    TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
    TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

    if (reply.negative_replies != 0)
        warnx("At least one token failed to cancel the key re-encryption.");

    /* Let the tool process  cancel the token object re-enciphering */
    hdr->flags = EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL;

    dest.process_id = getpid(); /* Send to current process only */
    dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
    memset(dest.token_label, ' ', sizeof(dest.token_label));

    rc = send_event(event_fd, EVENT_TYPE_MK_CHANGE_CANCEL,
                    EVENT_FLAGS_REPLY_REQ, payload_len, (char *)payload,
                    &dest, &reply);
    if (rc != 0) {
        warnx("Failed to send event: %d", rc);
        rc = EIO;
        goto out;
    }

    TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
    TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
    TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

    if (reply.negative_replies != 0)
        warnx("At least one token failed to cancel the key re-encryption.");

    rc = remove_mk_change_op();
    if (rc != 0)
        goto out;

    rc = EIO;

    goto out;
}

static int perform_reencipher(void)
{
    unsigned int i;
    int rc;

    /* Setup the MK change operation */
    TRACE_DEVEL("Num APQNs: %u\n", num_apqns);
    for (i = 0; i < num_apqns; i++) {
        TRACE_DEVEL("APQN: %02x.%04x\n", apqns[i].card, apqns[i].domain);
    }

    op.state = HSM_MK_CH_STATE_INITIAL;
    op.info.num_apqns = num_apqns;
    op.info.apqns = apqns;

    op.info.num_mkvps = 0;
    op.info.mkvps = mkvps;
    TRACE_DEVEL("EP11 WKVP set: %d\n", ep11_wkvp_set);
    if (ep11_wkvp_set) {
        TRACE_DEBUG_DUMP("EP11 WKVP: ", (CK_BYTE *)ep11_wkvp, EP11_WKVP_LENGTH);

        mkvps[op.info.num_mkvps].type = HSM_MK_TYPE_EP11;
        mkvps[op.info.num_mkvps].mkvp = ep11_wkvp;
        mkvps[op.info.num_mkvps].mkvp_len = EP11_WKVP_LENGTH;
        op.info.num_mkvps++;
    }
    TRACE_DEVEL("CCA SYM MKVP set: %d\n", cca_sym_mkvp_set);
    if (cca_sym_mkvp_set) {
        TRACE_DEBUG_DUMP("CCA SYM MKVP: ", (CK_BYTE *)cca_sym_mkvp, CCA_MKVP_LENGTH);

        mkvps[op.info.num_mkvps].type = HSM_MK_TYPE_CCA_SYM;
        mkvps[op.info.num_mkvps].mkvp = cca_sym_mkvp;
        mkvps[op.info.num_mkvps].mkvp_len = CCA_MKVP_LENGTH;
        op.info.num_mkvps++;
    }
    TRACE_DEVEL("CCA ASYM MKVP set: %d\n", cca_asym_mkvp_set);
     if (cca_asym_mkvp_set) {
         TRACE_DEBUG_DUMP("CCA ASYM MKVP: ", (CK_BYTE *)cca_asym_mkvp, CCA_MKVP_LENGTH);

         mkvps[op.info.num_mkvps].type = HSM_MK_TYPE_CCA_ASYM;
         mkvps[op.info.num_mkvps].mkvp = cca_asym_mkvp;
         mkvps[op.info.num_mkvps].mkvp_len = CCA_MKVP_LENGTH;
         op.info.num_mkvps++;

     }
    TRACE_DEVEL("CCA AES MKVP set: %d\n", cca_aes_mkvp_set);
    if (cca_aes_mkvp_set) {
        TRACE_DEBUG_DUMP("CCA SYM MKVP: ", (CK_BYTE *)cca_aes_mkvp, CCA_MKVP_LENGTH);

        mkvps[op.info.num_mkvps].type = HSM_MK_TYPE_CCA_AES;
        mkvps[op.info.num_mkvps].mkvp = cca_aes_mkvp;
        mkvps[op.info.num_mkvps].mkvp_len = CCA_MKVP_LENGTH;
        op.info.num_mkvps++;
    }
    TRACE_DEVEL("CCA APKA MKVP set: %d\n", cca_apka_mkvp_set);
    if (cca_apka_mkvp_set) {
        TRACE_DEBUG_DUMP("CCA SYM MKVP: ", (CK_BYTE *)cca_apka_mkvp, CCA_MKVP_LENGTH);

        mkvps[op.info.num_mkvps].type = HSM_MK_TYPE_CCA_APKA;
        mkvps[op.info.num_mkvps].mkvp = cca_apka_mkvp;
        mkvps[op.info.num_mkvps].mkvp_len = CCA_MKVP_LENGTH;
        op.info.num_mkvps++;
    }

    /* Check that no intersecting MK change operation is active */
    rc = check_intersecting_ops();
    if (rc != 0)
        return rc;

    /* Check that all tokens are present, warn & prompt user if not */
    rc = check_tokens_present();
    if (rc != 0)
        return rc;

    /* Create the MK change operation file */
    rc = create_mk_change_op();
    if (rc != 0)
        goto error;

    /* Query each token if it is affected by this MK change */
    rc = query_tokens_initiate_mk_change();
    if (rc != 0)
        goto error;

    /* Prompt for pin, login and open R/W session for each affected token */
    rc = login_tokens();
    if (rc != 0)
        goto error;

    /* Update MK operation with affected slots and state */
    op.state = HSM_MK_CH_STATE_REENCIPHERING;
    op.num_slots = num_affected_slots;
    op.slots = affected_slots;

    rc = save_mk_change_op();
    if (rc != 0)
        goto error;

    printf("Re-enciphering, please wait...\n");

    /* Let each affected token reencipher its keys */
    rc =  reencipher_tokens();
    if (rc != 0)
        goto error;

    printf("Completed.\n");

    /* Update MK operation state */
    op.state = HSM_MK_CH_STATE_REENCIPHERED;

    rc = save_mk_change_op();
    if (rc != 0)
        goto error;

    printf("\nMaster key change operation '%s' created.\n\n", op.id);
    printf("Once the new master keys have been set/activated:\n");
    printf(" - If you specified EXPECTED_MKVPS in your token configuration file(s),\n"
           "   you must now replace the old MKVPs with the new MKVPs.");
    printf(" - Run 'pkcshsm_mk_change finalize --id %s' when the new master\n"
           "   keys have been set/activated.\n", op.id);

    return 0;

error:
    if (op.id[0] != '\0') {
        /* Try to remove just created MK operation */
        hsm_mk_change_lock(true);
        hsm_mk_change_op_remove(op.id);
        hsm_mk_change_unlock();
    }

    return rc;
}

static int finalize_cancel_tokens(unsigned int event,
                                  enum hsm_mk_change_state state,
                                  const char *msg_cmd)
{
    size_t payload_len;
    unsigned char *payload = NULL;
    event_mk_change_data_t *hdr;
    struct event_destination dest;
    struct event_reply reply;
    int rc = 0;

    rc = build_event_payload(&payload, &payload_len);
    if (rc != 0)
        return rc;

    /*
     * Let the tool process cancel/finalize the token object re-enciphering.
     * Processes may still create new token objects at that time.
     */
    hdr = (event_mk_change_data_t *)payload;
    hdr->flags = EVENT_MK_CHANGE_FLAGS_TOK_OBJS;

    dest.process_id = getpid(); /* Send to current process only */
    dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
    memset(dest.token_label, ' ', sizeof(dest.token_label));

    memset(&reply, 0, sizeof(reply));

    rc = send_event(event_fd, event, EVENT_FLAGS_REPLY_REQ,
                    payload_len, (char *)payload,
                    &dest, &reply);
    if (rc != 0) {
        warnx("Failed to send event: %d", rc);
        rc = EIO;
        goto out;
    }

    TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
    TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
    TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

    if (reply.negative_replies != 0 || reply.positive_replies == 0) {
        warnx("At least one token failed to %s the master key change "
              "operation.", msg_cmd);
        warnx("Check the syslog for details about the errors reported by "
              "the tokens.");
        rc = EIO;
        goto out;
    }

    /*
     * Change state of MK change op. From now on, new processes will no longer
     * detect an active MK change operation. Any token objects created by such
     * new processes will use the new WK anyway, and will not have the
     * re-enciphered blob stored. Existing processes still running with the
     * MK change operation active using such token objects that have no
     * re-enciphered will use the normal blob, even though the MK change
     * operation might still be active and the new WK is set.
     */
    op.state = state;
    rc = save_mk_change_op();
    if (rc != 0)
        goto out;

    /*
     * Let all tokens cancel/finalize their session object re-enciphering.
     * This deactivates the MK change operation for the processes.
     */
    hdr->flags = EVENT_MK_CHANGE_FLAGS_NONE;

    dest.process_id = 0;
    dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
    memset(dest.token_label, ' ', sizeof(dest.token_label));

    memset(&reply, 0, sizeof(reply));

    rc = send_event(event_fd, event, EVENT_FLAGS_REPLY_REQ,
                    payload_len, (char *)payload,
                    &dest, &reply);
    if (rc != 0) {
        warnx("Failed to send event: %d", rc);
        rc = EIO;
        goto out;
    }

    TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
    TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
    TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

    if (reply.negative_replies != 0 || reply.positive_replies == 0) {
        warnx("At least one token failed to %s the master key change "
              "operation.", msg_cmd);
        warnx("Check the syslog for details about the errors reported by "
              "the tokens.");
        rc = EIO;
        goto out;
    }

    /*
     * Let the tool process cancel/finalize the token object re-enciphering
     * again to re-encipher token objects created by processes after the
     * initial token-object re-enciphering, but before the tokens deactivated
     * the MK change operation.
     */
    hdr->flags = EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL;

    dest.process_id = getpid(); /* Send to current process only */
    dest.token_type = EVENT_TOK_TYPE_CCA | EVENT_TOK_TYPE_EP11;
    memset(dest.token_label, ' ', sizeof(dest.token_label));

    memset(&reply, 0, sizeof(reply));

    rc = send_event(event_fd, event, EVENT_FLAGS_REPLY_REQ,
                    payload_len, (char *)payload,
                    &dest, &reply);
    if (rc != 0) {
        warnx("Failed to send event: %d", rc);
        rc = EIO;
        goto out;
    }

    TRACE_DEVEL("Positive: %lu\n", reply.positive_replies);
    TRACE_DEVEL("Negative: %lu\n", reply.negative_replies);
    TRACE_DEVEL("Not handled: %lu\n", reply.nothandled_replies);

    if (reply.negative_replies != 0 || reply.positive_replies == 0) {
        warnx("At least one token failed to %s the master key change "
              "operation.", msg_cmd);
        warnx("Check the syslog for details about the errors reported by "
              "the tokens.");
        rc = EIO;
        goto out;
    }

out:
    free(payload);

    return rc;
}


static int perform_finalize_cancel(bool cancel)
{
    CK_RV rv;
    int rc, rc2;
    unsigned int i, k;
    CK_ULONG num_affected = 0;

    TRACE_DEVEL("ID: '%s'\n", id);

    rv = load_mk_change_op(id);
    if (rv != CKR_OK) {
        warnx("HSM master key change operation '%s' not found.", id);
        return ENOENT;
    }

    if (op.state != HSM_MK_CH_STATE_REENCIPHERED &&
        op.state != HSM_MK_CH_STATE_ERROR ) {
        warnx("The HSM master key change operation '%s' is in a state where\n"
              "it can not be %s.", id, cancel ? "canceled": "finalized");
        return EINVAL;
    }

    /* Check if all affected tokens are able to finalize/cancel */
    rc = send_query_event(cancel ? EVENT_TYPE_MK_CHANGE_CANCEL_QUERY :
                                   EVENT_TYPE_MK_CHANGE_FINALIZE_QUERY,
                         cancel ? "cancel action" : "finalize action",
                         &num_affected);
    if (rc != 0)
        return rc;

    /* Ensure the affected slots are still the same */
    if (num_affected != op.num_slots) {
        warnx("The list of slots affected by this master key change has changed\n"
              "since initiating this master key change operation.");
        return EINVAL;
    }
    for (i = 0, k = 0; i < num_tokens && k < num_affected; i++) {
        if (tokens[i].affected == true) {
            if (op.slots[k] != tokens[i].id) {
                warnx("The list of slots affected by this master key change has changed\n"
                      "since initiating this master key change operation.");
                return EINVAL;
            }
            k++;
        }
    }

    /* Prompt for pin, login and open R/W session for each affected token */
    rc = login_tokens();
    if (rc != 0)
        return rc;

    printf("%s, please wait...\n", cancel ? "Canceling" : "Finalizing");

    /* Start finalizing/canceling */
    rc = finalize_cancel_tokens(cancel ? EVENT_TYPE_MK_CHANGE_CANCEL :
                                         EVENT_TYPE_MK_CHANGE_FINALIZE,
                                cancel ? HSM_MK_CH_STATE_CANCELING :
                                         HSM_MK_CH_STATE_FINALIZING,
                                cancel ? "cancel" : "finalize");
    if (rc != 0) {
        /* Set error state */
        op.state = HSM_MK_CH_STATE_ERROR;
        rc2 = save_mk_change_op();
        if (rc2 != 0)
            return rc2;

        return rc;
    }

    /* Operation complete, remove it */
    rc = remove_mk_change_op();
    if (rc != 0)
        return rc;

    printf("\nMaster key change operation '%s' successfully %s.\n",
           op.id, cancel ? "canceled" : "finalized");

    return 0;
}

static CK_RV perform_list_cb(struct hsm_mk_change_op *op, void *private)
{
    unsigned int i, j, k;
    int *first = private;
    struct hsm_mkvp *mkvps = NULL;
    unsigned int num_mkvps = 0;
    CK_RV rc;

    if (*first)
        *first = FALSE;
    else
        printf("\n");

    printf("Operation:       %s\n", op->id);

    switch (op->state) {
    case HSM_MK_CH_STATE_INITIAL:
        printf("    State:       Initial\n");
        break;
    case HSM_MK_CH_STATE_REENCIPHERING:
        printf("    State:       Re-enciphering of key objects ongoing\n");
        break;
    case HSM_MK_CH_STATE_REENCIPHERED:
        printf("    State:       Key objects have been re-enciphered,\n");
        printf("                 new master key(s) can now be set/activated\n");
        break;
    case HSM_MK_CH_STATE_FINALIZING:
        printf("    State:       Finalizing\n");
        break;
    case HSM_MK_CH_STATE_CANCELING:
        printf("    State:       Canceling\n");
        break;
    case HSM_MK_CH_STATE_ERROR:
        printf("    State:       Finalizing or canceling has errored\n");
        break;
    default:
        printf("    State:       Unknown\n");
        break;
    }

    printf("    APQNs:\n");
    for (i = 0; i < op->info.num_apqns; i++) {
        printf("        %02X.%04X\n", op->info.apqns[i].card,
               op->info.apqns[i].domain);
    }

    printf("    New master key verification patterns:\n");
    for (i = 0; i < op->info.num_mkvps; i++) {
        switch (op->info.mkvps[i].type) {
        case HSM_MK_TYPE_EP11:
            printf("        Type:    EP11\n");
            break;
        case HSM_MK_TYPE_CCA_SYM:
            printf("        Type:    CCA SYM\n");
            break;
        case HSM_MK_TYPE_CCA_ASYM:
            printf("        Type:    CCA ASYM\n");
            break;
        case HSM_MK_TYPE_CCA_AES:
            printf("        Type:    CCA AES\n");
            break;
        case HSM_MK_TYPE_CCA_APKA:
            printf("        Type:    CCA APKA\n");
            break;
        }
        printf("        MKVP:    ");
        for (k = 0; k < op->info.mkvps[i].mkvp_len; k++)
            printf("%02X", op->info.mkvps[i].mkvp[k]);
        printf("\n");
    }

    printf("    Affected slots:\n");
    for (i = 0; i < op->num_slots; i++) {
        printf("        Slot: %lu", op->slots[i]);
        for (k = 0; k < num_tokens; k++) {
            if (tokens[k].present && tokens[k].id == op->slots[i]) {
                printf(" Label: %.32s", tokens[k].info.label);
                break;
            }
        }
        printf("\n");

        rc = hsm_mk_change_token_mkvps_load(op->id, op->slots[i],
                                            &mkvps, &num_mkvps);
        if (rc == CKR_OK && num_mkvps > 0) {
            printf("            Current master key verification patterns:\n");
            for (j = 0; j < num_mkvps; j++) {
                switch (mkvps[j].type) {
                case HSM_MK_TYPE_EP11:
                    printf("                Type:    EP11\n");
                    break;
                case HSM_MK_TYPE_CCA_SYM:
                    printf("                Type:    CCA SYM\n");
                    break;
                case HSM_MK_TYPE_CCA_ASYM:
                    printf("                Type:    CCA ASYM\n");
                    break;
                case HSM_MK_TYPE_CCA_AES:
                    printf("                Type:    CCA AES\n");
                    break;
                case HSM_MK_TYPE_CCA_APKA:
                    printf("                Type:    CCA APKA\n");
                    break;
                }
                printf("                MKVP:    ");
                for (k = 0; k < mkvps[j].mkvp_len; k++)
                    printf("%02X", mkvps[j].mkvp[k]);
                printf("\n");
            }
            hsm_mk_change_mkvps_clean(mkvps, num_mkvps);
            free(mkvps);
        }
        mkvps = NULL;
        num_mkvps = 0;
    }

    return CKR_OK;
}

static int perform_list(void)
{
    CK_RV rv;
    int rc = 0;
    int first = TRUE;

    rv = hsm_mk_change_lock(false);
    if (rv != CKR_OK) {
        warnx("Failed to obtain lock");
        return EIO;
    }

    if (id != NULL) {
        TRACE_DEVEL("ID: '%s'\n", id);

        rv = hsm_mk_change_op_load(id, &op);
        if (rv != CKR_OK) {
            warnx("HSM master key change operation '%s' not found.", id);
            rc = ENOENT;
            goto out;
        }

        rv = perform_list_cb(&op, &first);
        hsm_mk_change_op_clean(&op);
        if (rv != CKR_OK) {
            warnx("Failed to list HSM master key change operation '%s'.", id);
            rc = EIO;
            goto out;
        }
    } else {
        rv = hsm_mk_change_op_iterate(perform_list_cb, &first);
        if (rv != CKR_OK) {
            warnx("Failed to list HSM master key change operations.");
            rc = EIO;
            goto out;
        }
    }

out:
    rv = hsm_mk_change_unlock();
    if (rv != CKR_OK) {
        warnx("Failed to release lock");
        return EIO;
    }

    return rc;
}

static int init_ock(void)
{
    void (*sym_ptr)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV rc;

    dll = dlopen(OCK_API_LIBNAME, DYNLIB_LDFLAGS);
    if (dll == NULL) {
#if defined(_AIX)
        int err = errno;
#else
        int err = ELIBACC;
#endif
        warnx("Error loading PKCS#11 library: dlopen: %s", dlerror());
        return err;
    }

    *(void **)(&sym_ptr) = dlsym(dll, "C_GetFunctionList");
    if (sym_ptr == NULL) {
#if defined(_AIX)
        int err = errno;
#else
        int err = ELIBACC;
#endif
        warnx("Error loading PKCS#11 library: dlsym(C_GetFunctionList): %s",
              dlerror());
        dlclose(dll);
        dll = NULL;
        return err;
    }

    sym_ptr(&func_list);
    if (func_list == NULL) {
        warnx("Error getting function list from PKCS11 library");
        dlclose(dll);
        dll = NULL;
        return ELIBACC;
    }

    rc = (func_list)->C_Initialize(NULL);
    if (rc != CKR_OK) {
        warnx("Error initializing the PKCS11 library: 0x%lX (%s)", rc,
               p11_get_ckr(rc));
        dlclose(dll);
        dll = NULL;
        func_list = NULL;
        return ELIBACC;
    }

    TRACE_INFO("PKCS#11 library initialized successfully\n");

    return 0;
}

static int get_token_infos(void)
{
    CK_RV rc;
    CK_ULONG num_slots, i;
    CK_SLOT_ID_PTR slots;

    rc = func_list->C_GetSlotList(FALSE, NULL, &num_slots);
    if (rc != CKR_OK) {
        warnx("Error getting number of slots: 0x%lX (%s)", rc,
               p11_get_ckr(rc));
        return EIO;
    }

    TRACE_DEVEL("Num Slots: %lu\n", num_slots);

    if (num_slots == 0) {
        warnx("C_GetSlotList returned 0 slots. Check that your tokens"
               " are installed correctly.");
        return EIO;
    }

    slots = calloc(num_slots, sizeof(CK_SLOT_ID));
    if (slots == NULL) {
        warnx("Failed to allocate slot list");
        return ENOMEM;
    }

    rc = func_list->C_GetSlotList(FALSE, slots, &num_slots);
    if (rc != CKR_OK) {
        warnx("Error getting slot list: 0x%lX (%s)", rc, p11_get_ckr(rc));
        free(slots);
        return EIO;
    }

    num_tokens = num_slots;
    tokens = calloc(num_tokens, sizeof(struct token_info));
    if (tokens == NULL) {
        warnx("Failed to allocate token list");
        free(slots);
        return ENOMEM;
    }

    for (i = 0; i < num_slots; i++) {
        TRACE_DEVEL("Slot %lu: %lu\n", i, slots[i]);

        tokens[i].id = slots[i];

        rc = func_list->C_GetTokenInfo(slots[i], &tokens[i].info);
        if (rc == CKR_TOKEN_NOT_PRESENT) {
            TRACE_DEVEL("  Token not present\n");
            continue;
        }
        if (rc != CKR_OK) {
            warnx("Error getting token infos for slot %lu: 0x%lX (%s)",
                  slots[i], rc, p11_get_ckr(rc));
            return 1;
        }

        TRACE_DEVEL("  Label: %.32s\n", tokens[i].info.label);
        TRACE_DEVEL("  Manufacturer: %.32s\n", tokens[i].info.manufacturerID);
        TRACE_DEVEL("  Model: %.16s\n", tokens[i].info.model);
        TRACE_DEVEL("  Serial Number: %.16s\n", tokens[i].info.serialNumber);

        tokens[i].present = true;
    }

    free(slots);
    return 0;
}

void sig_handler(int signal)
{
    UNUSED(signal);

    TRACE_DEVEL("Cntl-C ignored\n");
}

static void setup_signal_handler(void (*handler)(int signal))
{
    struct sigaction int_act;

    /* Set a handler for SIGINT/SIGTERM */
    memset(&int_act, 0, sizeof(int_act));
    if (handler != NULL)
        int_act.sa_handler = handler;
    else
        int_act.sa_handler = SIG_DFL;

    sigaction(SIGINT, &int_act, NULL);
    sigaction(SIGTERM, &int_act, NULL);
}

static int initialize(int cmd)
{
    int rc;
    CK_RV rv;

    setup_signal_handler(sig_handler);

    rv = hsm_mk_change_lock_create();
    if (rv != CKR_OK)
        return EIO;

    rc = init_ock();
    if (rc != 0)
        return rc;

    rc = get_token_infos();
    if (rc != 0)
        return rc;

    if (cmd == CMD_LIST)
        return 0;

    event_fd = init_event_client();
    if (event_fd < 0) {
        warnx("Failed to connect to pkcsslotd's event socket: %s",
              strerror(-event_fd));
        rc = -event_fd;
        return rc;
    }

    TRACE_INFO("Event connection established\n");

    return 0;
}

static void terminate(void)
{
    if (tokens != NULL) {
        if (func_list != NULL)
            logout_tokens();
        free(tokens);
    }

    if (affected_slots != NULL)
        free(affected_slots);

    if (apqns != NULL)
        free(apqns);

    if (event_fd >= 0)
        term_event_client(event_fd);

    if (dll != NULL) {
        func_list->C_Finalize(NULL);
        dlclose(dll);
    }

    hsm_mk_change_lock_destroy();

    setup_signal_handler(NULL);
}

static int verbose_str2level(char *str)
{
    const char *tlevel[] = {"none", "error", "warn", "info", "devel", "debug"};
    const int num = sizeof(tlevel) / sizeof(char *);
    int i;

    for (i = 0; i < num; i++) {
        if (strcmp(str, tlevel[i]) == 0) {
            return i;
        }
    }

    return -1;
}

int main(int argc, char **argv)
{
    int rc = 0, opt = 0;
    int cmd = 0;

    static const struct option long_opts[] = {
        {"apqns", required_argument, NULL, 'a'},
        {"ep11-wkvp", required_argument, NULL, 'e'},
        {"cca-sym-mkvp", required_argument, NULL, 's'},
        {"cca-asym-mkvp", required_argument, NULL, 'S'},
        {"cca-aes-mkvp", required_argument, NULL, 'A'},
        {"cca-apka-mkvp", required_argument, NULL, 'p'},
        {"id", required_argument, NULL, 'i'},
        {"verbose", required_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    if (argc >=2 && *argv[1] != '-') {
        if (strcmp(argv[1], "reencipher") == 0) {
            cmd = CMD_REENCIPHER;
        } else if (strcmp(argv[1], "finalize") == 0) {
            cmd = CMD_FINALIZE;
        } else if (strcmp(argv[1], "cancel") == 0) {
            cmd = CMD_CANCEL;
        } else if (strcmp(argv[1], "list") == 0) {
            cmd = CMD_LIST;
        } else {
            warnx("unrecognized command '%s'", argv[1]);
            exit(EXIT_FAILURE);
        }

        argv++;
        argc--;
    }

    while ((opt = getopt_long(argc, argv, "a:e:s:S:A:p:i:v:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a':
            if (cmd != CMD_REENCIPHER) {
                warnx("option -a/--apqns is only valid for the 'reencipher' command");
                exit(EXIT_FAILURE);
            }
            rc = parse_apqns(optarg);
            if (rc != 0)
                goto out;
            break;

        case 'e':
            if (cmd != CMD_REENCIPHER) {
                warnx("option -e/--ep11-wkvp is only valid for the 'reencipher' command");
                exit(EXIT_FAILURE);
            }
            rc = parse_mkvp(optarg, EP11_WKVP_LENGTH, ep11_wkvp,
                            &ep11_wkvp_set, "-e/--ep11-wkvp");
            if (rc != 0)
                goto out;
            break;

        case 's':
            if (cmd != CMD_REENCIPHER) {
                warnx("option -s/--cca-sym-mkvp is only valid for the 'reencipher' command");
                exit(EXIT_FAILURE);
            }
            rc = parse_mkvp(optarg, CCA_MKVP_LENGTH, cca_sym_mkvp,
                            &cca_sym_mkvp_set, "-s/--cca-sym-mkvp");
            if (rc != 0)
                goto out;
            break;

        case 'S':
            if (cmd != CMD_REENCIPHER) {
                warnx("option -S/--cca-asym-mkvp is only valid for the 'reencipher' command");
                exit(EXIT_FAILURE);
            }
            rc = parse_mkvp(optarg, CCA_MKVP_LENGTH, cca_asym_mkvp,
                            &cca_asym_mkvp_set, "-S/--cca-asym-mkvp");
            if (rc != 0)
                goto out;
            break;

        case 'A':
            if (cmd != CMD_REENCIPHER) {
                warnx("option -A/--cca-aes-mkvp is only valid for the 'reencipher' command");
                exit(EXIT_FAILURE);
            }
            rc = parse_mkvp(optarg, CCA_MKVP_LENGTH, cca_aes_mkvp,
                            &cca_aes_mkvp_set, "-A/--cca-aes-mkvp");
            if (rc != 0)
                goto out;
            break;

        case 'p':
            if (cmd != CMD_REENCIPHER) {
                warnx("option -p/--cca-apka-mkvp is only valid for the 'reencipher' command");
                exit(EXIT_FAILURE);
            }
            rc = parse_mkvp(optarg, CCA_MKVP_LENGTH, cca_apka_mkvp,
                            &cca_apka_mkvp_set, "-p/--cca-apka-mkvp");
            if (rc != 0)
                goto out;
            break;

        case 'i':
            if (cmd != CMD_FINALIZE && cmd != CMD_CANCEL && cmd != CMD_LIST) {
                warnx("option -i/--id is only valid for the 'finalize', 'cancel or 'list' command");
                exit(EXIT_FAILURE);
            }
            id = optarg;
            TRACE_DEVEL("ID: '%s'\n", id);
            break;

        case 'v':
            trace_level = verbose_str2level(optarg);
            if ((int)trace_level < 0) {
                warnx("Invalid verbose level '%s' specified.", optarg);
                exit(EXIT_FAILURE);
            }
            break;

        case 'h':
            usage(basename(argv[0]));
            exit(EXIT_SUCCESS);
        default:
            exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        warnx("unrecognized option '%s'", argv[optind]);
        exit(EXIT_FAILURE);
    }

    rc = initialize(cmd);
    if (rc != 0)
        goto out;

    switch (cmd) {
    case CMD_REENCIPHER:
        TRACE_DEVEL("Command: reencipher\n");

        if (apqns == NULL || num_apqns == 0) {
            warnx("option -a/--apqns is required for the 'reencipher' command");
            exit(EXIT_FAILURE);
        }
        if (!ep11_wkvp_set && !cca_sym_mkvp_set && !cca_asym_mkvp_set &&
            !cca_aes_mkvp_set && !cca_apka_mkvp_set) {
            warnx("at least one master key verification pattern must be specified");
            exit(EXIT_FAILURE);
        }

        rc = perform_reencipher();
        break;

    case CMD_FINALIZE:
        TRACE_DEVEL("Command: finalize\n");

        if (id == NULL) {
            warnx("option -i/--id is required for the 'finalize' command");
            exit(EXIT_FAILURE);
        }

        rc = perform_finalize_cancel(false);
        break;

    case CMD_CANCEL:
        TRACE_DEVEL("Command: cancel\n");

        if (id == NULL) {
            warnx("option -i/--id is required for the 'cancel' command");
            exit(EXIT_FAILURE);
        }

        rc = perform_finalize_cancel(true);
        break;

    case CMD_LIST:
        TRACE_DEVEL("Command: list\n");

        rc = perform_list();
        break;

    default:
        TRACE_DEVEL("Command: %d\n", cmd);
        warnx("no command specified");
        exit(EXIT_FAILURE);
    }

out:
    terminate();

    TRACE_DEVEL("rc: %d\n", rc);

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
