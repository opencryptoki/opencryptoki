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

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <signal.h>

#include <pkcs11types.h>
#include "p11util.h"
#include "event_client.h"
#include "pkcs_utils.h"
#include "hsm_mk_change.h"

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
        warnx("option %s must specify at least %lu bytes", option, min_size);
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
        warnx("option %s specifies more than %lu bytes, remaining bytes are ignored",
              option, min_size);

    *set = true;
    return 0;
}

static int perform_reencipher(void)
{
    unsigned int i;

    TRACE_DEVEL("Num APQNs: %u\n", num_apqns);
    for (i = 0; i < num_apqns; i++) {
        TRACE_DEVEL("APQN: %02x.%04x\n", apqns[i].card, apqns[i].domain);
    }
    TRACE_DEVEL("EP11 WKVP set: %d\n", ep11_wkvp_set);
    if (ep11_wkvp_set) {
        TRACE_DEBUG_DUMP("EP11 WKVP: ", (CK_BYTE *)ep11_wkvp, EP11_WKVP_LENGTH);
    }
    TRACE_DEVEL("CCA SYM MKVP set: %d\n", cca_sym_mkvp_set);
    if (cca_sym_mkvp_set) {
        TRACE_DEBUG_DUMP("CCA SYM MKVP: ", (CK_BYTE *)cca_sym_mkvp, CCA_MKVP_LENGTH);
    }
    TRACE_DEVEL("CCA ASYM MKVP set: %d\n", cca_asym_mkvp_set);
     if (cca_asym_mkvp_set) {
         TRACE_DEBUG_DUMP("CCA ASYM MKVP: ", (CK_BYTE *)cca_asym_mkvp, CCA_MKVP_LENGTH);
     }
    TRACE_DEVEL("CCA AES MKVP set: %d\n", cca_aes_mkvp_set);
    if (cca_aes_mkvp_set) {
        TRACE_DEBUG_DUMP("CCA SYM MKVP: ", (CK_BYTE *)cca_aes_mkvp, CCA_MKVP_LENGTH);
    }
    TRACE_DEVEL("CCA APKA MKVP set: %d\n", cca_apka_mkvp_set);
    if (cca_apka_mkvp_set) {
        TRACE_DEBUG_DUMP("CCA SYM MKVP: ", (CK_BYTE *)cca_apka_mkvp, CCA_MKVP_LENGTH);
    }

    // TODO

    return 0;
}

static int perform_finalize(void)
{
    TRACE_DEVEL("ID: '%s'\n", id);

    // TODO

    return 0;
}

static int perform_cancel(void)
{
    TRACE_DEVEL("ID: '%s'\n", id);

    // TODO

    return 0;
}

static int perform_list(void)
{
    if (id != NULL)
        TRACE_DEVEL("ID: '%s'\n", id);

    // TODO

    return 0;
}

static int init_ock(void)
{
    void (*sym_ptr)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV rc;

    dll = dlopen("libopencryptoki.so", RTLD_NOW);
    if (dll == NULL) {
        warnx("Error loading PKCS#11 library: dlopen: %s", dlerror());
        return ELIBACC;
    }

    *(void **)(&sym_ptr) = dlsym(dll, "C_GetFunctionList");
    if (sym_ptr == NULL) {
        warnx("Error loading PKCS#11 library: dlsym(C_GetFunctionList): %s",
              dlerror());
        dlclose(dll);
        dll = NULL;
        return ELIBACC;
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

    setup_signal_handler(sig_handler);

    rc = init_ock();
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
    if (apqns != NULL)
        free(apqns);

    if (event_fd >= 0)
        term_event_client(event_fd);

    if (dll != NULL) {
        func_list->C_Finalize(NULL);
        dlclose(dll);
    }

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

        rc = perform_finalize();
        break;

    case CMD_CANCEL:
        TRACE_DEVEL("Command: cancel\n");

        if (id == NULL) {
            warnx("option -i/--id is required for the 'cancel' command");
            exit(EXIT_FAILURE);
        }

        rc = perform_cancel();
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
