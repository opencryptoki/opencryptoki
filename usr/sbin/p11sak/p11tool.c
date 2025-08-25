/*
 * COPYRIGHT (c) International Business Machines Corp. 2025
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include "platform.h"

#if !defined(_AIX)
    #include <linux/limits.h>
#endif /* _AIX */

#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "p11tool.h"
#include "p11util.h"
#include "pin_prompt.h"
#include "mechtable.h"

void *p11tool_pkcs11_lib = NULL;
bool p11tool_pkcs11_initialized = false;
CK_FUNCTION_LIST *p11tool_pkcs11_funcs = NULL;
CK_SESSION_HANDLE p11tool_pkcs11_session = CK_INVALID_HANDLE;
CK_INFO p11tool_pkcs11_info;
CK_TOKEN_INFO p11tool_pkcs11_tokeninfo;
const struct p11tool_token_info *p11tool_token_info = NULL;
CK_SLOT_INFO p11tool_pkcs11_slotinfo;
char *p11tool_pin = NULL;

const struct p11tool_class p11tool_classes[] = {
    { .name = "CKO_DATA", .class = CKO_DATA, },
    { .name = "CKO_CERTIFICATE", .class = CKO_CERTIFICATE, },
    { .name = "CKO_PUBLIC_KEY", .class = CKO_PUBLIC_KEY, },
    { .name = "CKO_PRIVATE_KEY", .class = CKO_PRIVATE_KEY, },
    { .name = "CKO_SECRET_KEY", .class = CKO_SECRET_KEY, },
    { .name = "CKO_HW_FEATURE", .class = CKO_HW_FEATURE, },
    { .name = "CKO_DOMAIN_PARAMETERS", .class = CKO_DOMAIN_PARAMETERS, },
    { .name = "CKO_PROFILE", .class = CKO_PROFILE, },
    { .name = NULL, .class = 0, }
};

const struct p11tool_enum_value p11tool_ibm_dilithium_versions[] = {
    { .value = "r2_65", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND2_65 }, },
    { .value = "r2_87", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND2_87 }, },
    { .value = "r3_44", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND3_44 }, },
    { .value = "r3_65", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND3_65 }, },
    { .value = "r3_87", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND3_87 }, },
    { .value = NULL, },
};

const struct p11tool_enum_value p11tool_ibm_kyber_versions[] = {
    { .value = "r2_768", .args = NULL,
      .private = { .num = CK_IBM_KYBER_KEYFORM_ROUND2_768 }, },
    { .value = "r2_1024", .args = NULL,
      .private = { .num = CK_IBM_KYBER_KEYFORM_ROUND2_1024 }, },
    { .value = NULL, },
};

static bool p11tool_argument_is_set(const struct p11tool_arg *arg);

const struct p11tool_cmd *p11tool_find_command(const struct p11tool_cmd *cmds,
                                               const char *cmd)
{
    unsigned int i;

    for (i = 0; cmds[i].cmd != NULL; i++) {
        if (strcasecmp(cmd, cmds[i].cmd) == 0)
            return &cmds[i];
        if (cmds[i].cmd_short1 != NULL &&
            strcasecmp(cmd, cmds[i].cmd_short1) == 0)
            return &cmds[i];
        if (cmds[i].cmd_short2 != NULL &&
            strcasecmp(cmd, cmds[i].cmd_short2) == 0)
            return &cmds[i];
    }

    return NULL;
}

static void p11tool_count_opts(const struct p11tool_opt *opts,
                               unsigned int *optstring_len,
                               unsigned int *longopts_count)
{
    const struct p11tool_opt *opt;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            (*optstring_len)++;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                (*optstring_len)++;
                if (!opt->arg.required)
                    (*optstring_len)++;
            }
        }

        if (opt->long_opt != NULL)
            (*longopts_count)++;
    }
}

static CK_RV p11tool_build_opts(const struct p11tool_opt *opts,
                                char *optstring,
                                struct option *longopts)
{
    const struct p11tool_opt *opt;
    unsigned int opts_idx, long_idx;

    opts_idx = strlen(optstring);

    for (long_idx = 0; longopts[long_idx].name != NULL; long_idx++)
        ;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            optstring[opts_idx++] = opt->short_opt;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                optstring[opts_idx++] = ':';
                if (!opt->arg.required)
                    optstring[opts_idx++] = ':';
            }
        }

        if (opt->long_opt != NULL) {
            longopts[long_idx].name = opt->long_opt;
            longopts[long_idx].has_arg = opt->arg.type != ARG_TYPE_PLAIN ?
                              (opt->arg.required ?
                                      required_argument : optional_argument ) :
                              no_argument;
            longopts[long_idx].flag = NULL;
            longopts[long_idx].val = opt->short_opt != 0 ?
                                        opt->short_opt : opt->long_opt_val;
            long_idx++;
        }
    }

    return CKR_OK;
}

static void p11tool_count_arg_opts(const struct p11tool_arg *args,
                                   unsigned int *optstring_len,
                                   unsigned int *longopts_count)
{
    const struct p11tool_arg *arg;
    const struct p11tool_enum_value *val;

    for (arg = args; arg->name != NULL; arg++) {
        if (!p11tool_argument_is_set(arg))
            continue;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        for (val = arg->enum_values; val->value != NULL; val++) {
            if (val->opts == NULL)
                continue;

            if (*arg->value.enum_value != val)
                continue;

            p11tool_count_opts(val->opts, optstring_len, longopts_count);

            if (val->args != NULL)
                p11tool_count_arg_opts(val->args, optstring_len,
                                      longopts_count);
        }
    }
}

static CK_RV p11tool_build_arg_opts(const struct p11tool_arg *args,
                                    char *optstring,
                                    struct option *longopts)
{
    const struct p11tool_arg *arg;
    const struct p11tool_enum_value *val;
    CK_RV rc;

    for (arg = args; arg->name != NULL; arg++) {
        if (!p11tool_argument_is_set(arg))
            continue;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        for (val = arg->enum_values; val->value != NULL; val++) {
            if (val->opts == NULL)
                continue;

            if (*arg->value.enum_value != val)
                continue;

            rc = p11tool_build_opts(val->opts, optstring, longopts);
            if (rc != CKR_OK)
                return rc;

            if (val->args != NULL) {
                rc = p11tool_build_arg_opts(val->args, optstring, longopts);
                if (rc != CKR_OK)
                    return rc;
            }
        }
    }

    return CKR_OK;
}

static CK_RV p11tool_build_cmd_opts(const struct p11tool_opt *cmd_opts,
                                    const struct p11tool_opt *generic_opts,
                                    const struct p11tool_arg *cmd_args,
                                    char **optstring, struct option **longopts)
{
    unsigned int optstring_len = 0, longopts_count = 0;
    CK_RV rc;

    p11tool_count_opts(generic_opts, &optstring_len, &longopts_count);
    if (cmd_opts != NULL)
        p11tool_count_opts(cmd_opts, &optstring_len, &longopts_count);
    if (cmd_args != NULL)
        p11tool_count_arg_opts(cmd_args, &optstring_len, &longopts_count);

    *optstring = calloc(1 + optstring_len + 1, 1);
    *longopts = calloc(longopts_count + 1, sizeof(struct option));
    if (*optstring == NULL || *longopts == NULL) {
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    (*optstring)[0] = ':'; /* Let getopt return ':' on missing argument */

    rc = p11tool_build_opts(generic_opts, *optstring, *longopts);
    if (rc != CKR_OK)
        goto error;

    if (cmd_opts != NULL) {
        rc = p11tool_build_opts(cmd_opts, *optstring, *longopts);
        if (rc != CKR_OK)
            goto error;
    }

    if (cmd_args != NULL) {
        rc = p11tool_build_arg_opts(cmd_args, *optstring, *longopts);
        if (rc != CKR_OK)
            goto error;
    }

    return CKR_OK;

error:
    if (*optstring != NULL)
        free(*optstring);
    *optstring = NULL;

    if (*longopts != NULL)
        free(*longopts);
    *longopts = NULL;

    return rc;
}

static CK_RV p11tool_process_plain_argument(const struct p11tool_arg *arg)
{
    *arg->value.plain = true;

    return CKR_OK;
}

static CK_RV p11tool_process_string_argument(const struct p11tool_arg *arg,
                                             char *val)
{
    *arg->value.string = val;

    return CKR_OK;
}

static CK_RV p11tool_process_enum_argument(const struct p11tool_arg *arg,
                                           char *val)
{
    const struct p11tool_enum_value *enum_val, *any_val = NULL;

    for (enum_val = arg->enum_values; enum_val->value != NULL; enum_val++) {

        if (enum_val->any_value != NULL) {
            any_val = enum_val;
        } else if (arg->case_sensitive ?
                            strcmp(val, enum_val->value) == 0 :
                            strcasecmp(val, enum_val->value) == 0) {
            *arg->value.enum_value = (struct p11tool_enum_value *)enum_val;
            return CKR_OK;
        }
    }

    /* process ANY enumeration value after all others */
    if (any_val != NULL) {
        *any_val->any_value = val;
        *arg->value.enum_value = (struct p11tool_enum_value *)any_val;
        return CKR_OK;
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV p11tool_process_number_argument(const struct p11tool_arg *arg,
                                             char *val)
{
    char *endptr;

    errno = 0;
    *arg->value.number = strtoul(val, &endptr, 0);

    if ((errno == ERANGE && *arg->value.number == ULONG_MAX) ||
        (errno != 0 && *arg->value.number == 0) ||
        endptr == val) {
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV p11tool_processs_argument(const struct p11tool_arg *arg, char *val)
{
    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return p11tool_process_plain_argument(arg);
    case ARG_TYPE_STRING:
        return p11tool_process_string_argument(arg, val);
    case ARG_TYPE_ENUM:
        return p11tool_process_enum_argument(arg, val);
    case ARG_TYPE_NUMBER:
        return p11tool_process_number_argument(arg, val);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

static bool p11tool_argument_is_set(const struct p11tool_arg *arg)
{
    if (arg->is_set != NULL)
       return arg->is_set(arg);

    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return *arg->value.plain;
    case ARG_TYPE_STRING:
        return *arg->value.string != NULL;
    case ARG_TYPE_ENUM:
        return *arg->value.enum_value != NULL;
    case ARG_TYPE_NUMBER:
        return *arg->value.number != 0;
    default:
        return false;
    }
}

static void p11tool_option_arg_error(const struct p11tool_opt *opt,
                                     const char *arg)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '-%c/--%s'", arg,
             opt->short_opt, opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '--%s'", arg, opt->long_opt);
    else
        warnx("Invalid argument '%s' for option '-%c'", arg, opt->short_opt);
}

static void p11tool_option_missing_error(const struct p11tool_opt *opt)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Option '-%c/--%s' is required but not specified", opt->short_opt,
             opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Option '--%s is required but not specified'", opt->long_opt);
    else
        warnx("Option '-%c' is required but not specified", opt->short_opt);
}

static CK_RV p11tool_process_option(const struct p11tool_opt *opts,
                                    int ch, char *val)
{
    const struct p11tool_opt *opt;
    CK_RV rc;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (ch == (opt->short_opt != 0 ? opt->short_opt : opt->long_opt_val)) {
            rc = p11tool_processs_argument(&opt->arg, val);
            if (rc != CKR_OK) {
                p11tool_option_arg_error(opt, val);
                return rc;
            }

            return CKR_OK;
        }
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV p11tool_process_arg_option(const struct p11tool_arg *args,
                                        int ch, char *value)
{
    const struct p11tool_arg *arg;
    const struct p11tool_enum_value *val;
    CK_RV rc;

    for (arg = args; arg->name != NULL; arg++) {
        if (!p11tool_argument_is_set(arg))
            continue;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        for (val = arg->enum_values; val->value != NULL; val++) {
            if (val->opts == NULL)
                continue;

            if (*arg->value.enum_value != val)
                continue;

            rc = p11tool_process_option(val->opts, ch, value);
            if (rc != CKR_OK)
                return rc;

            if (val->args != NULL) {
                rc = p11tool_process_arg_option(val->args, ch, value);
                if (rc != CKR_OK)
                    return rc;
            }
        }
    }

    return CKR_OK;
}

static CK_RV p11tool_process_cmd_option(const struct p11tool_opt *cmd_opts,
                                        const struct p11tool_arg *cmd_args,
                                        const struct p11tool_opt *generic_opts,
                                        int opt, char *arg)
{
    CK_RV rc;

    rc = p11tool_process_option(generic_opts, opt, arg);
    if (rc == CKR_OK)
        return CKR_OK;

    if (cmd_opts != NULL) {
        rc = p11tool_process_option(cmd_opts, opt, arg);
        if (rc == CKR_OK)
            return CKR_OK;
    }

    if (cmd_args != NULL) {
        rc = p11tool_process_arg_option(cmd_args, opt, arg);
        if (rc == CKR_OK)
            return CKR_OK;
    }

    return rc;
}

static CK_RV p11tool_check_required_opts(const struct p11tool_opt *opts)
{
    const struct p11tool_opt *opt;
    CK_RV rc = CKR_OK;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->required && opt->arg.required &&
            p11tool_argument_is_set(&opt->arg) == false) {
            p11tool_option_missing_error(opt);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing options */
        }
    }

    return rc;
}

static CK_RV p11tool_check_required_arg_opts(const struct p11tool_arg *args)
{
    const struct p11tool_arg *arg;
    const struct p11tool_enum_value *val;
    CK_RV rc;

    for (arg = args; arg->name != NULL; arg++) {
        if (!p11tool_argument_is_set(arg))
            continue;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        for (val = arg->enum_values; val->value != NULL; val++) {
            if (val->opts == NULL)
                continue;

            if (*arg->value.enum_value != val)
                continue;

            rc = p11tool_check_required_opts(val->opts);
            if (rc != CKR_OK)
                return rc;

            if (val->args != NULL) {
                rc = p11tool_check_required_arg_opts(val->args);
                if (rc != CKR_OK)
                    return rc;
            }
        }
    }

    return CKR_OK;
}

CK_RV p11tool_check_required_cmd_opts(const struct p11tool_opt *cmd_opts,
                                      const struct p11tool_arg *cmd_args,
                                      const struct p11tool_opt *generic_opts)
{
    CK_RV rc, rc2;

    rc = p11tool_check_required_opts(generic_opts);
    if (rc != CKR_OK)
        return rc;

    if (cmd_opts != NULL) {
        rc2 = p11tool_check_required_opts(cmd_opts);
        if (rc == CKR_OK)
            rc = rc2;
    }

    if (cmd_args != NULL) {
        rc2 = p11tool_check_required_arg_opts(cmd_args);
        if (rc == CKR_OK)
            rc = rc2;
    }

    return rc;
}

CK_RV p11tool_parse_cmd_options(const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int argc, char *argv[])
{
    char *optstring = NULL;
    struct option *longopts = NULL;
    CK_RV rc;
    int c;

    rc = p11tool_build_cmd_opts(cmd != NULL ? cmd->opts : NULL, generic_opts,
                                cmd != NULL ? cmd->args : NULL,
                                &optstring, &longopts);
    if (rc != CKR_OK)
        goto done;

    opterr = 0;
    while (1) {
        c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1)
            break;

        switch (c) {
        case ':':
            warnx("Option '%s' requires an argument", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        case '?': /* An invalid option has been specified */
            if (optopt)
                warnx("Invalid option '-%c'", optopt);
            else
                warnx("Invalid option '%s'", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        default:
            rc = p11tool_process_cmd_option(cmd != NULL ? cmd->opts : NULL,
                                            cmd != NULL ? cmd->args : NULL,
                                            generic_opts, c, optarg);
            if (rc != CKR_OK)
                goto done;
            break;
        }
    }

    if (optind < argc) {
        warnx("Invalid argument '%s'", argv[optind]);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

done:
    if (optstring != NULL)
        free(optstring);
    if (longopts != NULL)
        free(longopts);

    return rc;
}

CK_RV p11tool_check_required_args(const struct p11tool_arg *args)
{
    const struct p11tool_arg *arg;
    CK_RV rc2, rc = CKR_OK;

    for (arg = args; arg != NULL && arg->name != NULL; arg++) {
        if (arg->required && p11tool_argument_is_set(arg) == false) {
            warnx("Argument '%s' is required but not specified", arg->name);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing arguments */
        }

        /* Check enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc2 = p11tool_check_required_args((*arg->value.enum_value)->args);
            if (rc2 != CKR_OK)
                rc = rc2;
            /* No break, report all missing arguments */
        }
    }

    return rc;
}

static CK_RV p11tool_parse_arguments(const struct p11tool_arg *args,
                                     int *argc, char **argv[])
{
    const struct p11tool_arg *arg;
    CK_RV rc = CKR_OK;

    for (arg = args; arg->name != NULL; arg++) {
        if (*argc < 2 || strncmp((*argv)[1], "-", 1) == 0)
            break;

        rc = p11tool_processs_argument(arg, (*argv)[1]);
        if (rc != CKR_OK) {
            if (rc == CKR_ARGUMENTS_BAD)
                warnx("Invalid argument '%s' for '%s'", (*argv)[1], arg->name);
            break;
        }

        (*argc)--;
        (*argv)++;

        /* Process enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc = p11tool_parse_arguments((*arg->value.enum_value)->args,
                                         argc, argv);
            if (rc != CKR_OK)
                break;
        }
    }

    return rc;
}

CK_RV p11tool_parse_cmd_arguments(const struct p11tool_cmd *cmd,
                                  int *argc, char **argv[])
{
    if (cmd == NULL)
        return CKR_OK;

    return p11tool_parse_arguments(cmd->args, argc, argv);
}

void p11tool_print_indented(const char *str, int indent)
{
    char *word, *line, *desc, *desc_ptr;
    int word_len, pos = indent;

    desc = desc_ptr = strdup(str);
    if (desc == NULL)
        return;

    line = strsep(&desc, "\n");
    while (line != NULL) {
        word = strsep(&line, " ");
        pos = indent;
        while (word != NULL) {
            word_len = strlen(word);
            if (pos + word_len + 1 > MAX_PRINT_LINE_LENGTH) {
                printf("\n%*s", indent, "");
                pos = indent;
            }
            if (pos == indent)
                printf("%s", word);
            else
                printf(" %s", word);
            pos += word_len + 1;
            word = strsep(&line, " ");
        }
        if (desc)
            printf("\n%*s", indent, "");
        line =  strsep(&desc, "\n");
    }

    printf("\n");
    free(desc_ptr);
}

static void p11tool_print_options_help(const struct p11tool_opt *opts,
                                       int indent_pos)
{
    const struct p11tool_enum_value *val;
    const struct p11tool_opt *opt;
    char tmp[200];
    int len;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp), "-%c, --%s", opt->short_opt,
                           opt->long_opt);
        else if (opt->short_opt == 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp),"    --%s", opt->long_opt);
        else
            len = snprintf(tmp, sizeof(tmp),"-%c", opt->short_opt);

        if (len >= (int)sizeof(tmp) || len < 0) {
            warnx("Error formatting option string. Skipping.\n");
            continue;
        }

        if (opt->arg.type != ARG_TYPE_PLAIN) {
            if (opt->arg.required)
                snprintf(&tmp[len], sizeof(tmp) - len, " %s", opt->arg.name);
            else if (opt->long_opt == NULL)
                snprintf(&tmp[len], sizeof(tmp) - len, "[%s]", opt->arg.name);
            else
                snprintf(&tmp[len], sizeof(tmp) - len, "[=%s]", opt->arg.name);
        }

        printf("    %-*.*s ", indent_pos - 5, indent_pos - 5, tmp);
        p11tool_print_indented(opt->description, indent_pos);

        if (opt->arg.type == ARG_TYPE_ENUM) {
            for (val = opt->arg.enum_values; val->value != NULL; val++) {
                printf("%*s    %s\n", indent_pos, "", val->value);
            }
        }
    }
}

static void p11tool_print_arguments_help(const struct p11tool_cmd *cmd,
                                         const struct p11tool_arg *args,
                                         int indent, int indent_pos)
{
    const struct p11tool_arg *arg;
    const struct p11tool_enum_value *val;
    int width;
    bool newline = false;

    if (indent > 0) {
        for (arg = args; arg->name != NULL; arg++) {
            if (arg->required)
                printf(" %s", arg->name);
            else
                printf(" [%s]", arg->name);
        }
        printf("\n\n");
    }

    for (arg = args; arg->name != NULL; arg++) {
        width = indent_pos - 5 - indent;
        if (width < (int)strlen(arg->name))
            width = (int)strlen(arg->name);

        printf("%*s    %-*.*s ", indent, "", width, width, arg->name);
        p11tool_print_indented(arg->description, indent_pos);

        newline = false;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        /* Enumeration: print possible values */
        for (val = arg->enum_values; val->value != NULL; val++) {
            if (arg == cmd->args && p11tool_argument_is_set(arg) &&
                *arg->value.enum_value != val)
                continue;

            newline = true;

            width = indent_pos - 9 - indent;
            if (width < (int)strlen(val->value))
                width = (int)strlen(val->value);

            printf("%*s        %-*.*s ", indent, "", width, width, val->value);
            if (val->description) {
                p11tool_print_indented(val->description, indent_pos);
                newline = false;
            }

            if (val->args != NULL) {
                p11tool_print_arguments_help(cmd, val->args, indent + 8,
                                             indent_pos);
                newline = false;
            } else if (val->description == NULL) {
                printf("\n");
            }
        }
    }

    if (indent > 0 || newline)
        printf("\n");
}

static void p11tool_print_argument_options_help(const struct p11tool_arg *args,
                                                int indent_pos)
{
    const struct p11tool_arg *arg;
    const struct p11tool_enum_value *val;

    for (arg = args; arg->name != NULL; arg++) {
        if (arg->type != ARG_TYPE_ENUM)
            continue;

        for (val = arg->enum_values; val->value != NULL; val++) {
            if (val->opts == NULL)
                continue;

            if (p11tool_argument_is_set(arg) && *arg->value.enum_value != val)
                continue;

            printf("\nOPTIONS FOR ARGUMENT '%s' VALUE '%s':\n",
                   arg->name, val->value);

            p11tool_print_options_help(val->opts, indent_pos);

            if (val->args != NULL)
                p11tool_print_argument_options_help(val->args, indent_pos);
        }
    }
}

void p11tool_print_help(const char *name,
                        const struct p11tool_cmd *commands,
                        const struct p11tool_opt *generic_opts,
                        int indent_pos)
{
    const struct p11tool_cmd *cmd;

    printf("\n");
    printf("Usage: %s COMMAND [ARGS] [OPTIONS]\n", name);
    printf("\n");
    printf("COMMANDS:\n");
    for (cmd = commands; cmd->cmd != NULL; cmd++) {
        printf("    %-*.*s ", indent_pos - 5, indent_pos - 5, cmd->cmd);
        p11tool_print_indented(cmd->description, indent_pos);
    }
    printf("\n");
    printf("COMMON OPTIONS\n");
    p11tool_print_options_help(generic_opts, indent_pos);
    printf("\n");
    printf("For more information use '%s COMMAND --help'.\n", name);
    printf("\n");
}

void p11tool_print_command_help(const char *name,
                                const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int indent_pos)
{
    printf("\n");
    printf("Usage: %s %s [ARGS] [OPTIONS]\n", name, cmd->cmd);
    printf("\n");
    printf("ARGS:\n");
    p11tool_print_arguments_help(cmd, cmd->args, 0, indent_pos);
    printf("OPTIONS:\n");
    p11tool_print_options_help(cmd->opts, indent_pos);
    p11tool_print_options_help(generic_opts, indent_pos);
    p11tool_print_argument_options_help(cmd->args, indent_pos);
    printf("\n");
    if (cmd->help != NULL)
        cmd->help();
}

void p11tool_print_version(const char *name)
{
    printf("%s version %s\n", name, PACKAGE_VERSION);
}

void p11tool_print_bool_attr_short(const CK_ATTRIBUTE *val, bool applicable)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
        val->ulValueLen != sizeof(CK_BBOOL))
        applicable = false;
    printf("%c ", applicable ? (*(CK_BBOOL *)(val->pValue) ? '1' : '0') : '-');
}

void p11tool_print_bool_attr_long(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)||
        val->ulValueLen != sizeof(CK_BBOOL))
        return;

    printf("%*s%s: %s\n", indent, "", attr,
           sensitive ? "[sensitive]" :
                   *(CK_BBOOL *)(val->pValue) ? "CK_TRUE" : "CK_FALSE");
}

void p11tool_print_utf8_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        printf("%*s%s: \"%.*s\"\n", indent, "", attr, (int)val->ulValueLen,
               (char *)val->pValue);
    }
}

void p11tool_print_java_midp_secdom_attr(const char *attr,
                                         const CK_ATTRIBUTE *val,
                                         int indent, bool sensitive)
{
    CK_JAVA_MIDP_SECURITY_DOMAIN secdom;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
        return;
    } else if (val->ulValueLen != sizeof(CK_JAVA_MIDP_SECURITY_DOMAIN)) {
        return;
    }

    secdom = *(CK_JAVA_MIDP_SECURITY_DOMAIN *)(val->pValue);

    switch (secdom) {
    case CK_SECURITY_DOMAIN_UNSPECIFIED:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_SECURITY_DOMAIN_UNSPECIFIED");
        break;
    case CK_SECURITY_DOMAIN_MANUFACTURER:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_SECURITY_DOMAIN_MANUFACTURER");
        break;
    case CK_SECURITY_DOMAIN_OPERATOR:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_SECURITY_DOMAIN_OPERATOR");
        break;
    case CK_SECURITY_DOMAIN_THIRD_PARTY:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_SECURITY_DOMAIN_THIRD_PARTY");
        break;
    default:
        printf("%*s%s: 0x%lX\n", indent, "", attr,
               *(CK_JAVA_MIDP_SECURITY_DOMAIN *)(val->pValue));
        break;
    }
}

void p11tool_print_cert_category_attr(const char *attr, const CK_ATTRIBUTE *val,
                                      int indent, bool sensitive)
{
    CK_CERTIFICATE_CATEGORY category;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
        return;
    } else if (val->ulValueLen != sizeof(CK_CERTIFICATE_CATEGORY)) {
        return;
    }

    category = *(CK_CERTIFICATE_CATEGORY *)(val->pValue);

    switch (category) {
    case CK_CERTIFICATE_CATEGORY_UNSPECIFIED:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_CERTIFICATE_CATEGORY_UNSPECIFIED");
        break;
    case CK_CERTIFICATE_CATEGORY_TOKEN_USER:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_CERTIFICATE_CATEGORY_TOKEN_USER");
        break;
    case CK_CERTIFICATE_CATEGORY_AUTHORITY:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_CERTIFICATE_CATEGORY_AUTHORITY");
        break;
    case CK_CERTIFICATE_CATEGORY_OTHER_ENTITY:
        printf("%*s%s: %s\n", indent, "", attr,
               "CK_CERTIFICATE_CATEGORY_OTHER_ENTITY");
        break;
    default:
        printf("%*s%s: 0x%lX\n", indent, "", attr,
               *(CK_CERTIFICATE_CATEGORY *)(val->pValue));
        break;
    }
}

void p11tool_print_dump(CK_BYTE *p, CK_ULONG len, int indent)
{
    CK_ULONG i;

    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("\n%*s%02X ", indent, "", p[i]);
        else
            printf("%02X ", p[i]);
    }
    printf("\n");
}

void p11tool_print_byte_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                   int indent, bool sensitive)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        printf("%*s%s: len=%lu value:", indent, "", attr,
               val->ulValueLen);
        p11tool_print_dump((CK_BYTE *)val->pValue, val->ulValueLen, indent + 4);
    }
}

void p11tool_print_x509_name_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive)
{
    X509_NAME *name = NULL;
    const unsigned char *tmp_ptr;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
        return;
    }

    tmp_ptr = (const unsigned char *)val->pValue;
    name = d2i_X509_NAME(NULL, &tmp_ptr, val->ulValueLen);
    if (name != NULL) {
        char *oneline = X509_NAME_oneline(name, NULL, 0);
        if (oneline != NULL) {
            printf("%*s%s: %s\n", indent, "", attr, oneline);
            OPENSSL_free(oneline);
        }
        printf("%*s len=%lu value:", indent + 3, "", val->ulValueLen);
        p11tool_print_dump((CK_BYTE *)val->pValue, val->ulValueLen, indent + 4);
    } else {
        p11tool_print_byte_array_attr(attr, val, indent, false);
    }

    if (name != NULL)
        X509_NAME_free(name);
}

void p11tool_print_x509_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive)
{
    X509 *x509 = NULL;
    const unsigned char *tmp_ptr;
    char buf[256];
    BIO *bio;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
        return;
    }

    bio = BIO_new(BIO_s_mem());
    tmp_ptr = (const unsigned char *)val->pValue;
    x509 = d2i_X509(NULL, &tmp_ptr, val->ulValueLen);
    if (x509 != NULL) {
        printf("%*s%s: \n", indent, "", attr);
        if (bio != NULL) {
            X509_print(bio, x509);
            while (BIO_gets(bio, buf, sizeof(buf)))
                printf("%*s%s", indent + 4, "", buf);
            printf("%*s len=%lu value:", indent + 3, "", val->ulValueLen);
        }
        p11tool_print_dump((CK_BYTE *)val->pValue, val->ulValueLen, indent + 4);
    } else {
        p11tool_print_byte_array_attr(attr, val, indent, false);
    }

    if (bio != NULL)
        BIO_free(bio);
    if (x509 != NULL)
        X509_free(x509);
}

void p11tool_print_x509_serial_number_attr(const char *attr,
                                           const CK_ATTRIBUTE *val,
                                           int indent, bool sensitive)
{
    ASN1_INTEGER *serialno = NULL;
    const unsigned char *tmp_ptr;
    BIGNUM *bn_serialno = NULL;
    CK_BYTE *serial_buf = NULL;
    CK_ULONG serial_len;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
        return;
    }

    tmp_ptr = (const unsigned char *)val->pValue;
    serialno = d2i_ASN1_INTEGER(NULL, &tmp_ptr, val->ulValueLen);
    if (serialno != NULL &&
        (bn_serialno = ASN1_INTEGER_to_BN(serialno, NULL)) != NULL) {
        serial_len = BN_num_bytes(bn_serialno);
        serial_buf = OPENSSL_malloc(serial_len);
        if (serial_buf != NULL &&
            BN_bn2bin(bn_serialno, serial_buf) == (int)serial_len) {
            printf("%*s%s: len=%lu value:", indent, "", attr,
                   serial_len);
            p11tool_print_dump(serial_buf, serial_len, indent + 4);
        } else {
            p11tool_print_byte_array_attr(attr, val, indent, false);
        }
    } else {
        p11tool_print_byte_array_attr(attr, val, indent, false);
    }

    if (bn_serialno != NULL)
        BN_free(bn_serialno);
    if (serial_buf != NULL)
        OPENSSL_free(serial_buf);
    if (serialno != NULL)
        ASN1_INTEGER_free(serialno);
}

void p11tool_print_ulong_attr(const char *attr, const CK_ATTRIBUTE *val,
                              int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_ULONG))
        return;

    if (sensitive)
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    else
        printf("%*s%s: %lu (0x%lX)\n", indent, "", attr,
               *(CK_ULONG *)(val->pValue), *(CK_ULONG *)(val->pValue));
}

void p11tool_print_date_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_DATE))
        return;

    if (sensitive)
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    else
        printf("%*s%s: %.4s-%.2s-%.2s\n", indent, "", attr,
               ((CK_DATE *)(val->pValue))->year,
               ((CK_DATE *)(val->pValue))->month,
               ((CK_DATE *)(val->pValue))->day);
}

void p11tool_print_mech_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_MECHANISM_TYPE))
        return;

    if (sensitive)
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    else if (*(CK_MECHANISM_TYPE *)(val->pValue) == CK_UNAVAILABLE_INFORMATION)
        printf("%*s%s: [information unavailable]\n", indent, "", attr);
    else
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr,
               p11_get_ckm(&mechtable_funcs,
                           *(CK_MECHANISM_TYPE *)(val->pValue)),
               *(CK_MECHANISM_TYPE *)(val->pValue));
}

void p11tool_print_mech_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                   int indent, bool sensitive)
{
    unsigned int i, num;

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        (val->ulValueLen % sizeof(CK_MECHANISM_TYPE)) != 0)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else {
        num = val->ulValueLen / sizeof(CK_MECHANISM_TYPE);
        if (num == 0 && val->type == CKA_ALLOWED_MECHANISMS) {
            printf("%*s%s: [no restriction]\n", indent, "", attr);
            return;
        }

        printf("%*s%s: %u mechanisms\n", indent, "", attr, num);
        for (i = 0; i < num; i++) {
            printf("%*s- %s (0x%lX)\n", indent + 4, "",
                   p11_get_ckm(&mechtable_funcs,
                               ((CK_MECHANISM_TYPE *)(val->pValue))[i]),
                   ((CK_MECHANISM_TYPE *)(val->pValue))[i]);
        }
    }
}

void p11tool_print_oid(const CK_BYTE *oid, CK_ULONG oid_len, bool long_name)
{
    ASN1_OBJECT *obj = NULL;
    char buf[250];
    int nid;

    if (d2i_ASN1_OBJECT(&obj, &oid, oid_len) == NULL) {
        printf("[invalid object ID]");
        return;
    }

    nid = OBJ_obj2nid(obj);

    if (OBJ_obj2txt(buf, sizeof(buf), obj, 1) <= 0) {
        printf("[error]");
        ASN1_OBJECT_free(obj);
        return;
    }

    printf("oid=%s", buf);
    if (long_name && nid != NID_undef)
        printf(" (%s)", OBJ_nid2ln(nid));

    ASN1_OBJECT_free(obj);
}

void p11tool_print_ibm_dilithium_keyform_attr(const char *attr,
                                              const CK_ATTRIBUTE *val,
                                              int indent, bool sensitive)
{
    const struct p11tool_enum_value *eval;
    const char *name = "[unknown]";

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
         val->ulValueLen != sizeof (CK_ULONG)) &&
        !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        for (eval = p11tool_ibm_dilithium_versions;
                                                eval->value != NULL; eval++) {
            if (eval->private.num == *(CK_ULONG *)(val->pValue)) {
                name = eval->value;
                break;
            }
        }
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_ULONG *)(val->pValue));
    }
}

void p11tool_print_ibm_kyber_keyform_attr(const char *attr,
                                          const CK_ATTRIBUTE *val,
                                          int indent, bool sensitive)
{
    const struct p11tool_enum_value *eval;
    const char *name = "[unknown]";

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
         val->ulValueLen != sizeof (CK_ULONG)) &&
        !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        for (eval = p11tool_ibm_kyber_versions; eval->value != NULL; eval++) {
            if (eval->private.num == *(CK_ULONG *)(val->pValue)) {
                name = eval->value;
                break;
            }
        }
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_ULONG *)(val->pValue));
    }
}

void p11tool_print_class_attr(const char *attr, const CK_ATTRIBUTE *val,
                              int indent, bool sensitive)
{
    const struct p11tool_class *cls;
    const char *name = NULL;

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_OBJECT_CLASS))
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    }

    for (cls = p11tool_classes; cls->name  != NULL; cls++) {
        if (*(CK_OBJECT_CLASS *)(val->pValue) == cls->class) {
            name = cls->name;
            break;
        }
    }

    if (name != NULL)
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_OBJECT_CLASS *)(val->pValue));
    else
        printf("%*s%s: 0x%lX\n", indent, "", attr,
               *(CK_OBJECT_CLASS *)(val->pValue));
}

int p11tool_openssl_err_cb(const char *str, size_t len, void *u)
{
    UNUSED(u);

    if (str[len - 1] == '\n')
        len--;

    warnx("OpenSSL error: %.*s", (int)len, str);
    return 1;
}

void p11tool_print_oid_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        printf("%*s%s: ", indent, "", attr);
        p11tool_print_oid(val->pValue, val->ulValueLen, true);
        printf(" len=%lu value:", val->ulValueLen);
        p11tool_print_dump((CK_BYTE *)val->pValue,val->ulValueLen, indent + 4);
    }
}

void p11tool_free_attributes(CK_ATTRIBUTE *attrs, CK_ULONG num_attrs)
{
    CK_ULONG i;

    if (attrs == NULL)
        return;

    for (i = 0; i < num_attrs; i++) {
        if (attrs[i].pValue != NULL) {
            OPENSSL_cleanse(attrs[i].pValue, attrs[i].ulValueLen);
            free(attrs[i].pValue);
        }
    }

    free(attrs);
}

bool p11tool_is_attr_array_attr(CK_ATTRIBUTE *attr)
{
    switch (attr->type) {
    case CKA_WRAP_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
    case CKA_DERIVE_TEMPLATE:
        return true;

    default:
        return false;
    }
}

void p11tool_free_attr_array_attr(CK_ATTRIBUTE *attr)
{
    CK_ULONG i, num;
    CK_ATTRIBUTE *elem;

    num = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
    for (i = 0, elem = attr->pValue; elem != NULL && i < num; i++, elem++) {
        if (elem->pValue != NULL) {
            if (p11tool_is_attr_array_attr(elem))
                p11tool_free_attr_array_attr(elem);
            free(elem->pValue);
            elem->pValue = NULL;
        }
    }
}

CK_RV p11tool_alloc_attr_array_attr(CK_ATTRIBUTE *attr, bool *allocated)
{
    CK_ULONG i, num;
    CK_ATTRIBUTE *elem;
    CK_RV rc;

    *allocated = false;

    num = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
    for (i = 0, elem = attr->pValue; i < num; i++, elem++) {
        if (elem->ulValueLen > 0 && elem->pValue == NULL) {
            elem->pValue = calloc(elem->ulValueLen, 1);
            if (elem->pValue == NULL) {
                p11tool_free_attr_array_attr(attr);
                return CKR_HOST_MEMORY;
            }

            *allocated = true;
            continue;
        }

        if (p11tool_is_attr_array_attr(elem)) {
            rc = p11tool_alloc_attr_array_attr(elem, allocated);
            if (rc != CKR_OK) {
                p11tool_free_attr_array_attr(attr);
                return CKR_HOST_MEMORY;
            }
        }
    }

    return CKR_OK;
}

CK_RV p11tool_add_attribute(CK_ATTRIBUTE_TYPE type, const void *value,
                            CK_ULONG value_len, CK_ATTRIBUTE **attrs,
                            CK_ULONG *num_attrs)
{
    CK_ATTRIBUTE *tmp;

    tmp = realloc(*attrs, (*num_attrs + 1) * sizeof(CK_ATTRIBUTE));
    if (tmp == NULL) {
        warnx("Failed to allocate memory for attribute list");
        return CKR_HOST_MEMORY;
    }

    *attrs = tmp;

    tmp[*num_attrs].type = type;
    tmp[*num_attrs].ulValueLen = value_len;
    tmp[*num_attrs].pValue = NULL;
    if (value_len != 0) {
        tmp[*num_attrs].pValue = malloc(value_len);
        if (tmp[*num_attrs].pValue == NULL) {
            warnx("Failed to allocate memory attribute to add to list");
            return CKR_HOST_MEMORY;
        }
        memcpy(tmp[*num_attrs].pValue, value, value_len);
    }

    (*num_attrs)++;

    return CKR_OK;
}

CK_RV p11tool_add_bignum_attr(CK_ATTRIBUTE_TYPE type, const BIGNUM* bn,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    int len;
    CK_BYTE *buff = NULL;
    CK_RV rc;

    len = BN_num_bytes(bn);
    buff = calloc(len, 1);
    if (buff == NULL || len == 0) {
        warnx("Failed to allocate a buffer for a bignum");
        if (buff != NULL)
            free(buff);
        return CKR_HOST_MEMORY;
    }

    if (BN_bn2bin(bn, buff) != len) {
        warnx("Failed to get a bignum.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        free(buff);
        return CKR_FUNCTION_FAILED;
    }

    rc = p11tool_add_attribute(type, buff, len, attrs, num_attrs);
    free(buff);

    return rc;
}

CK_RV p11tool_add_attributes(const struct p11tool_objtype *objtype,
                             const struct p11tool_attr *bool_attrs,
                             CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                             const char *label, const char *attr_string,
                             const char *id, bool is_sensitive, bool so,
                             CK_RV (*add_attrs)(
                                     const struct p11tool_objtype *objtype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private),
                             void *private,
                             bool (*attr_applicable)(
                                     const struct p11tool_objtype *objtype,
                                     const struct p11tool_attr *attr))
{
    const CK_BBOOL ck_true = TRUE;
    bool found;
    CK_ULONG i;
    CK_RV rc;

    rc = p11tool_add_attribute(CKA_LABEL, label, strlen(label),
                               attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add %s key attribute CKA_LABEL: 0x%lX: %s",
              objtype->name, rc, p11_get_ckr(rc));
        return rc;
    }

    rc = p11tool_add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true),
                               attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add %s key attribute CKA_TOKEN: 0x%lX: %s",
              objtype->name, rc, p11_get_ckr(rc));
        return rc;
    }

    rc = p11tool_parse_boolean_attrs(objtype, bool_attrs, attr_string,
                                     attrs, num_attrs, true, so,
                                     attr_applicable);
    if (rc != CKR_OK)
        return rc;

    if (id != NULL) {
        rc = p11tool_parse_id(id, attrs, num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    if (add_attrs != NULL) {
        rc = add_attrs(objtype, attrs, num_attrs, private);
        if (rc != CKR_OK) {
            warnx("Failed to add %s key attributes: 0x%lX: %s",
                  objtype->name, rc, p11_get_ckr(rc));
            return rc;
        }
    }

    if (is_sensitive) {
        /* Add CKA_SENSITIVE=TRUE if its not already in attribute list */
        for (i = 0, found = false; i < *num_attrs && !found; i++) {
            if ((*attrs)[i].type == CKA_SENSITIVE)
                found = true;
        }

        if (!found) {
            rc = p11tool_add_attribute(CKA_SENSITIVE, &ck_true, sizeof(ck_true),
                                       attrs, num_attrs);
            if (rc != CKR_OK) {
                warnx("Failed to add %s key attribute CKA_SENSITIVE: 0x%lX: %s",
                      objtype->name, rc, p11_get_ckr(rc));
                return rc;
            }
        }
    }

    return CKR_OK;
}

CK_RV p11tool_parse_hex(const char *id_string, CK_BYTE **buf, CK_ULONG *buflen)
{
    CK_RV rc = CKR_OK;
    BIGNUM *b = NULL;
    int len;

    *buflen = 0;
    *buf = NULL;

    len = BN_hex2bn(&b, id_string);
    if (len < (int)strlen(id_string) || len == 0 || b == NULL) {
        warnx("Hex string '%s' is not valid", id_string);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    len = len / 2 + (len % 2 > 0 ? 1 : 0);
    *buf = calloc(1, len);
    if (*buf == NULL) {
        warnx("Failed to allocate memory for buffer");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (BN_bn2binpad(b, *buf, len) != len) {
        warnx("Failed to prepare the value for CKA_ID attribute");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *buflen = len;

done:
    if (rc != CKR_OK && *buf != NULL) {
        free(*buf);
        *buf = NULL;
    }
    if (b != NULL)
        BN_free(b);

    return rc;
}

CK_RV p11tool_parse_id(const char *id_string, CK_ATTRIBUTE **attrs,
                       CK_ULONG *num_attrs)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len;
    CK_RV rc;

    rc = p11tool_parse_hex(id_string, &buf, &len);
    if (rc != CKR_OK)
        return rc;

    rc = p11tool_add_attribute(CKA_ID, buf, len, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add attribute CKA_ID: 0x%lX: %s", rc, p11_get_ckr(rc));
        goto done;
    }

done:
    if (buf != NULL)
        free(buf);

    return rc;
}

const struct p11tool_attr *p11tool_find_attr_by_letter(
                                        const struct p11tool_attr *bool_attrs,
                                        char letter)
{
    const struct p11tool_attr *attr;

    for (attr = bool_attrs; attr->name != NULL; attr++) {
        if (attr->letter == toupper(letter))
            return attr;
    }

    return NULL;
}

CK_RV p11tool_parse_boolean_attrs(const struct p11tool_objtype *objtype,
                                  const struct p11tool_attr *bool_attrs,
                                  const char *attr_string, CK_ATTRIBUTE **attrs,
                                  CK_ULONG *num_attrs, bool check_settable,
                                  bool so,
                                  bool (*attr_applicable)(
                                         const struct p11tool_objtype *objtype,
                                         const struct p11tool_attr *attr))
{
    const struct p11tool_attr *attr;
    unsigned int i = 0;
    CK_BBOOL val;
    CK_RV rc;

    if (attr_string == NULL)
        return CKR_OK;

    for (i = 0; attr_string[i] != '\0'; i++) {
        attr = p11tool_find_attr_by_letter(bool_attrs, attr_string[i]);
        if (attr == NULL) {
            warnx("Attribute '%c' is not valid", attr_string[i]);
            return CKR_ARGUMENTS_BAD;
        }

        /* silently ignore attributes that are not settable or not applicable */
        if ((check_settable && !attr->settable) ||
            (attr_applicable != NULL && objtype != NULL &&
             !attr_applicable(objtype, attr)))
            continue;

        val = isupper(attr_string[i]) ? CK_TRUE : CK_FALSE;

        if (check_settable && attr->so_set_to_true &&
            val == CK_TRUE && !so) {
            warnx("Attribute %s ('%c') can only be set to TRUE by SO",
                  attr->name, attr->letter);
            return CKR_ARGUMENTS_BAD;
        }

        rc = p11tool_add_attribute(attr->type, &val, sizeof(val),
                                   attrs, num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

CK_RV p11tool_get_attribute(CK_OBJECT_HANDLE key, CK_ATTRIBUTE *attr)
{
    bool allocated;
    CK_RV rc;

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session,
                                                   key, attr, 1);
    if (rc != CKR_OK)
        return rc;

    if (attr->pValue == NULL && attr->ulValueLen > 0) {
        attr->pValue = calloc(attr->ulValueLen, 1);
        if (attr->pValue == NULL)
            return CKR_HOST_MEMORY;

        rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session,
                                                       key, attr, 1);
    }

    if (p11tool_is_attr_array_attr(attr) && rc == CKR_OK &&
        attr->pValue != NULL && attr->ulValueLen > 0) {
        do {
            allocated = false;
            rc = p11tool_alloc_attr_array_attr(attr, &allocated);
            if (rc != CKR_OK)
                return rc;

            if (!allocated)
                break;

            rc = p11tool_pkcs11_funcs->C_GetAttributeValue(
                                                   p11tool_pkcs11_session, key,
                                                   attr, 1);
        } while (rc == CKR_OK);
    }

    return rc;
}

CK_RV p11tool_get_bignum_attr(CK_OBJECT_HANDLE key, CK_ATTRIBUTE_TYPE type,
                              BIGNUM **bn)
{
    CK_ATTRIBUTE attr;
    CK_RV rc;

    attr.type = type;
    attr.pValue = NULL;
    attr.ulValueLen = 0;

    if (p11tool_is_attr_array_attr(&attr))
        return CKR_ATTRIBUTE_TYPE_INVALID;

    rc = p11tool_get_attribute(key, &attr);
    if (rc != CKR_OK)
        return rc;

    if (attr.ulValueLen == 0 || attr.pValue == NULL)
        return CKR_ATTRIBUTE_VALUE_INVALID;

    /* Caller may supply an already allocated BIGNUM, allocate if NULL. */
    if (*bn == NULL) {
        *bn = BN_new();
        if (*bn == NULL) {
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    if (BN_bin2bn((unsigned char *)attr.pValue, attr.ulValueLen, *bn) == NULL) {
        rc = CKR_FUNCTION_FAILED;
        BN_free(*bn);
        *bn = NULL;
        goto done;
    }

done:
    OPENSSL_cleanse(attr.pValue, attr.ulValueLen);
    free(attr.pValue);

    return rc;
}

CK_RV p11tool_get_common_name_value(CK_OBJECT_HANDLE obj, char *label,
                                    char **common_name_value)
{
    CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
    X509 *x509 = NULL;
    const CK_BYTE *tmp_ptr;
    char *subj = NULL, *cn_tmp, *cn_tmp2 = NULL;
    CK_RV rc;

    rc = p11tool_get_attribute(obj, &attr);
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_VALUE from object "
              "\"%s\": 0x%lX: %s", label, rc, p11_get_ckr(rc));
        return rc;
    }

    if (attr.ulValueLen == 0 || attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        *common_name_value = strdup("[not available]");
        if (*common_name_value == NULL) {
            warnx("Failed to allocate memory for common_name_value "
                  "for object \"%s\"", label);
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    tmp_ptr = attr.pValue;
    x509 = d2i_X509(NULL, &tmp_ptr, attr.ulValueLen);
    if (x509 == NULL) {
        *common_name_value = strdup("[not available]");
        if (*common_name_value == NULL) {
            warnx("Failed to allocate memory for common_name_value "
                  "for object \"%s\"", label);
            rc = CKR_HOST_MEMORY;
        } else {
            rc = CKR_OK;
        }
        goto done;
    }

    subj = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
    if (subj == NULL) {
        *common_name_value = strdup("[not available]");
        if (*common_name_value == NULL) {
            warnx("Failed to allocate memory for common_name_value "
                  "for object \"%s\"", label);
            rc = CKR_HOST_MEMORY;
        } else {
            rc = CKR_OK;
        }
        goto done;
    }

    *common_name_value = strdup(subj);
    if (*common_name_value == NULL) {
        warnx("Failed to allocate memory for common_name attribute"
              "for object \"%s\"", label);
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    cn_tmp = strstr(subj, "/CN=");
    if (cn_tmp != NULL) {
        cn_tmp2 = *common_name_value;
        *common_name_value = strdup(cn_tmp + 4);
        if (*common_name_value == NULL) {
            warnx("Failed to allocate memory for common_name attribute"
                  "for object \"%s\"", label);
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    rc = CKR_OK;

done:
    free(attr.pValue);
    if (subj != NULL)
        OPENSSL_free(subj);
    if (x509 != NULL)
        X509_free(x509);
    if (cn_tmp2 != NULL)
        free(cn_tmp2);

    return rc;
}

CK_RV p11tool_get_keysize_value(CK_OBJECT_HANDLE obj, char *label,
                                const struct p11tool_objtype *objtype_val,
                                CK_ULONG *keysize_val)
{
    CK_ATTRIBUTE keysize_attr;
    CK_RV rc;

    if (objtype_val->keysize_attr == (CK_ATTRIBUTE_TYPE)-1) {
        *keysize_val = 0;
        return CKR_OK;
    }

    keysize_attr.type = objtype_val->keysize_attr;
    if (!objtype_val->keysize_attr_value_len) {
        keysize_attr.ulValueLen = sizeof(*keysize_val);
        keysize_attr.pValue = keysize_val;
    } else {
        /* Query attribute length only */
        keysize_attr.ulValueLen = 0;
        keysize_attr.pValue = NULL;
    }

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, obj,
                                                   &keysize_attr, 1);
    if (rc != CKR_OK) {
        warnx("Attribute %s is not available in object \"%s\"",
              p11_get_cka(keysize_attr.type), label);
        return rc;
    }

    if (objtype_val->keysize_attr_value_len)
        *keysize_val = keysize_attr.ulValueLen;

    if (objtype_val->key_keysize_adjust != NULL)
        *keysize_val = objtype_val->key_keysize_adjust(objtype_val,
                                                       *keysize_val);

    return CKR_OK;
}

CK_RV p11tool_get_typestr_value(CK_OBJECT_CLASS class_val, CK_ULONG keysize_val,
                                const struct p11tool_objtype *objtype_val,
                                char *label, char **typestr)
{
    int rv;

    switch (class_val) {
    case CKO_SECRET_KEY:
        if (keysize_val != 0)
            rv = asprintf(typestr, "%s %lu", objtype_val->name, keysize_val);
        else
            rv = asprintf(typestr, "%s", objtype_val->name);
        break;
    case CKO_PUBLIC_KEY:
        if (keysize_val != 0)
            rv = asprintf(typestr, "public %s %lu", objtype_val->name,
                          keysize_val);
        else
            rv = asprintf(typestr, "public %s", objtype_val->name);
        break;
    case CKO_PRIVATE_KEY:
        if (keysize_val != 0)
            rv = asprintf(typestr, "private %s %lu", objtype_val->name,
                          keysize_val);
        else
            rv = asprintf(typestr, "private %s", objtype_val->name);
        break;
    case CKO_CERTIFICATE:
        rv = asprintf(typestr, "%s", objtype_val->name);
        break;
    default:
        warnx("%s object \"%s\" has an unsupported %s class: %lu",
              objtype_val->obj_liststr, label,
              objtype_val->obj_typestr, class_val);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (*typestr == NULL || rv < 0) {
        warnx("Failed to allocate type string buffer");
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

CK_RV p11tool_get_class_and_type_values(CK_OBJECT_HANDLE obj, char *label,
                                       CK_OBJECT_CLASS *class_val,
                                       CK_ULONG *otype_val)
{
    CK_RV rc;
    CK_KEY_TYPE ktype_val = 0;
    CK_CERTIFICATE_TYPE ctype_val = 0;
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, class_val, sizeof(class_val) },
        { CKA_KEY_TYPE, &ktype_val, sizeof(ktype_val) },
        { CKA_CERTIFICATE_TYPE, &ctype_val, sizeof(ctype_val) },
    };
    const CK_ULONG num_attrs = sizeof(attrs) / sizeof(CK_ATTRIBUTE);

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, obj,
                                                   attrs, num_attrs);
    if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID &&
        rc != CKR_ATTRIBUTE_SENSITIVE) {
        warnx("Failed to get attributes: C_GetAttributeValue: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        return rc;
    }

    /* Class attribute must be available in any case. Others
       depend on object type: key or certificate */
    if (attrs[0].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        warnx("Class attribute %s is not available in object \"%s\"",
              p11_get_cka(attrs[0].type), label);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (attrs[1].ulValueLen != CK_UNAVAILABLE_INFORMATION)
        *otype_val = ktype_val;
    else if (attrs[2].ulValueLen != CK_UNAVAILABLE_INFORMATION)
        *otype_val = ctype_val;
    else {
        warnx("At least one of CKA_KEY_TYPE or CKA_CERTIFICATE_TYPE must "
              "be available in object \"%s\"", label);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    return CKR_OK;
}

CK_RV p11tool_get_label_value(CK_OBJECT_HANDLE obj, char** label_value)
{
    CK_ATTRIBUTE attr = { CKA_LABEL, NULL, 0 };
    CK_RV rv;

    if (label_value == NULL)
        return CKR_ARGUMENTS_BAD;

    rv = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, obj,
                                                   &attr, 1);
    if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID &&
        rv != CKR_ATTRIBUTE_SENSITIVE) {
        warnx("Failed to get CKA_LABEL attribute (length only): "
              "C_GetAttributeValue: 0x%lX: %s", rv, p11_get_ckr(rv));
        return rv;
    }

    if (attr.ulValueLen == 0 ||
        attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        attr.pValue = strdup("");
        if (attr.pValue == NULL) {
            warnx("Failed to allocate memory for label attribute");
            return CKR_HOST_MEMORY;
        } else {
            goto done;
        }
    }

    attr.pValue = calloc(attr.ulValueLen + 1, 1);
    if (attr.pValue == NULL) {
        warnx("Failed to allocate memory for label attribute");
        return CKR_HOST_MEMORY;
    }

    rv = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, obj,
                                                   &attr, 1);
    if (rv != CKR_OK) {
        warnx("Failed to get CKA_LABEL attribute: C_GetAttributeValue: 0x%lX: %s",
              rv, p11_get_ckr(rv));
        free(attr.pValue);
        return rv;
    }

done:
    *label_value = attr.pValue;

    return CKR_OK;
}

CK_BBOOL p11tool_objclass_expected(CK_OBJECT_HANDLE obj,
                                   enum p11tool_objclass objclass)
{
    CK_OBJECT_CLASS class_val = 0;
    CK_ATTRIBUTE attr = { CKA_CLASS, &class_val, sizeof(class_val) };
    CK_RV rv;

    rv = p11tool_get_attribute(obj, &attr);
    if (rv != CKR_OK) {
        warnx("Failed to get CKA_CLASS attribute: p11tool_get_attribute: 0x%lX: %s",
              rv, p11_get_ckr(rv));
        return rv;
    }

    switch (objclass) {
    case OBJCLASS_KEY:
        if (class_val == CKO_SECRET_KEY || class_val == CKO_PUBLIC_KEY ||
            class_val == CKO_PRIVATE_KEY)
            return CK_TRUE;
        break;
    case OBJCLASS_CERTIFICATE:
        if (class_val == CKO_CERTIFICATE)
            return CK_TRUE;
        break;
    default:
        break;
    }

    return CK_FALSE;
}

bool p11tool_attr_applicable_for_certtype(
                                        const struct p11tool_objtype *certtype,
                                        const struct p11tool_attr *attr)
{
    UNUSED(certtype);

    switch (attr->type) {
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
    case CKA_DESTROYABLE:
    case CKA_TRUSTED:
        return true;
    default:
        break;
    }

    return false;
}

bool p11tool_attr_applicable_for_keytype(const struct p11tool_objtype *keytype,
                                         const struct p11tool_attr *attr)
{
    switch (attr->type) {
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
        return keytype->sign_verify;

    case CKA_ENCRYPT:
    case CKA_DECRYPT:
        return keytype->encrypt_decrypt;

    case CKA_WRAP:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_UNWRAP:
        return keytype->wrap_unwrap;

    case CKA_DERIVE:
        return keytype->derive;

    default:
        return true;
    }
}

bool p11tool_cert_attr_applicable(const struct p11tool_objtype *certtype,
                                  const struct p11tool_attr *attr)
{
    return p11tool_attr_applicable_for_certtype(certtype, attr);
}

bool p11tool_secret_attr_applicable(const struct p11tool_objtype *objtype,
                                    const struct p11tool_attr *attr)
{
    return attr->secret && p11tool_attr_applicable_for_keytype(objtype, attr);
}

bool p11tool_public_attr_applicable(const struct p11tool_objtype *objtype,
                                    const struct p11tool_attr *attr)
{
    return attr->public && p11tool_attr_applicable_for_keytype(objtype, attr);
}

bool p11tool_private_attr_applicable(const struct p11tool_objtype *objtype,
                                     const struct p11tool_attr *attr)
{
    return attr->private && p11tool_attr_applicable_for_keytype(objtype, attr);
}

static const struct p11tool_token_info *p11tool_find_known_token(
                                 const CK_TOKEN_INFO *info,
                                 const struct p11tool_token_info *known_tokens)
{
    unsigned int i;
    char manufacturer[sizeof(info->manufacturerID) + 1] = { 0 };
    char model[sizeof(info->model) + 1]  = { 0 };
    char *ch;

    if (known_tokens == NULL)
        return NULL;

    memcpy(manufacturer, info->manufacturerID, sizeof(info->manufacturerID));
    ch = strchr(manufacturer, ' ');
    if (ch != NULL)
        *ch = '\0';

    memcpy(model, info->model, sizeof(info->model));
    ch = strchr(model, ' ');
    if (ch != NULL)
        *ch = '\0';

    for (i = 0; known_tokens[i].type != TOKTYPE_UNKNOWN; i++) {
        if (strcmp(manufacturer, known_tokens[i].manufacturer) == 0 &&
            strcmp(model, known_tokens[i].model) == 0)
            return &known_tokens[i];
    }

    return NULL;
}

static CK_RV p11tool_load_pkcs11_lib(void)
{
    CK_RV rc;
    CK_RV (*getfunclist)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    const char *libname;

    libname = secure_getenv(P11TOOL_PKCSLIB_ENV_NAME);
    if (libname == NULL || strlen(libname) < 1)
        libname = P11TOOL_DEFAULT_PKCS11_LIB;

    p11tool_pkcs11_lib = dlopen(libname, DYNLIB_LDFLAGS);
    if (p11tool_pkcs11_lib == NULL) {
        warnx("Failed to load PKCS#11 library '%s': %s", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    *(void**) (&getfunclist) = dlsym(p11tool_pkcs11_lib, "C_GetFunctionList");
    if (getfunclist == NULL) {
        warnx("Failed to resolve symbol '%s' from PKCS#11 library '%s': %s",
              "C_GetFunctionList", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    rc = getfunclist(&p11tool_pkcs11_funcs);
    if (rc != CKR_OK) {
        warnx("C_GetFunctionList() on PKCS#11 library '%s' failed with 0x%lX: "
              "%s)\n", libname, rc, p11_get_ckr(rc));
        return CKR_FUNCTION_FAILED;
    }

    if (p11tool_pkcs11_funcs == NULL) {
        warnx("C_GetFunctionList() on PKCS#11 library '%s' failed\n", libname);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV p11tool_open_pkcs11_session(CK_SLOT_ID slot, CK_FLAGS flags,
                                         const char *pin,
                                         CK_USER_TYPE user_type,
                                         const struct p11tool_token_info
                                                                 *known_tokens)
{
    CK_RV rc;

    rc = p11tool_pkcs11_funcs->C_GetInfo(&p11tool_pkcs11_info);
    if (rc != CKR_OK) {
        warnx("Failed to getPKCS#11 info: C_GetInfo: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        return rc;
    }

    rc = p11tool_pkcs11_funcs->C_GetSlotInfo(slot, &p11tool_pkcs11_slotinfo);
    if (rc != CKR_OK) {
        warnx("Slot %lu is not available: C_GetSlotInfo: 0x%lX: %s", slot,
              rc, p11_get_ckr(rc));
        return rc;
    }

    rc = p11tool_pkcs11_funcs->C_GetTokenInfo(slot, &p11tool_pkcs11_tokeninfo);
    if (rc != CKR_OK) {
        warnx("Token at slot %lu is not available: C_GetTokenInfo: 0x%lX: %s",
              slot, rc, p11_get_ckr(rc));
        return rc;
    }

    p11tool_token_info = p11tool_find_known_token(&p11tool_pkcs11_tokeninfo,
                                                  known_tokens);

    rc = p11tool_pkcs11_funcs->C_OpenSession(slot, flags, NULL, NULL,
                                             &p11tool_pkcs11_session);
    if (rc != CKR_OK) {
        warnx("Opening a session failed: C_OpenSession: 0x%lX: %s)", rc,
              p11_get_ckr(rc));
        return rc;
    }

    if (pin != NULL) {
        rc = p11tool_pkcs11_funcs->C_Login(p11tool_pkcs11_session, user_type,
                                           (CK_CHAR *)pin, strlen(pin));
        if (rc != CKR_OK && rc != CKR_USER_ALREADY_LOGGED_IN) {
            warnx("Login failed: C_Login: 0x%lX: %s", rc, p11_get_ckr(rc));
            return rc;
        }
    }

    return CKR_OK;
}

static void p11tool_close_pkcs11_session(void)
{
    CK_RV rc;

    rc = p11tool_pkcs11_funcs->C_Logout(p11tool_pkcs11_session);
    if (rc != CKR_OK && rc != CKR_USER_NOT_LOGGED_IN)
        warnx("C_Logout failed: 0x%lX: %s", rc, p11_get_ckr(rc));

    rc = p11tool_pkcs11_funcs->C_CloseSession(p11tool_pkcs11_session);
    if (rc != CKR_OK)
        warnx("C_CloseSession failed: 0x%lX: %s", rc, p11_get_ckr(rc));

    p11tool_pkcs11_session = CK_INVALID_HANDLE;
}

CK_RV p11tool_init_pkcs11(const struct p11tool_cmd *command, bool no_login,
                          const char *pin, bool force_pin_prompt, bool so,
                          bool remember_pin, CK_SLOT_ID slot,
                          const struct p11tool_token_info *known_tokens)
{
    CK_RV rc;
    char *buf_user_pin = NULL;

    if (command == NULL || command->session_flags == 0)
        return CKR_OK;

    if (no_login) {
        if (pin != NULL) {
            warnx("Option '-p'/'--pin' is not allowed with '-N'/'--no-login'");
            return CKR_ARGUMENTS_BAD;
        }
        if (force_pin_prompt) {
            warnx("Option '--force-pin-prompt' is not allowed with "
                  "'-N'/'--no-login'");
            return CKR_ARGUMENTS_BAD;
        }
        if (so) {
            warnx("Option '--so' is not allowed with '-N'/'--no-login'");
            return CKR_ARGUMENTS_BAD;
        }
        pin = NULL;
    } else {
        if (pin == NULL)
            pin = getenv(so ? PKCS11_SO_PIN_ENV_NAME :
                                        PKCS11_USER_PIN_ENV_NAME);
        if (force_pin_prompt || pin == NULL)
            pin = pin_prompt(&buf_user_pin, so ? "Please enter SO PIN: " :
                                                 "Please enter user PIN: ");
        if (pin == NULL)
            return CKR_FUNCTION_FAILED;
    }

    if (!so && !no_login && remember_pin) {
        p11tool_pin = strdup(pin);
        if (p11tool_pin == NULL) {
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    rc = p11tool_load_pkcs11_lib();
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_pkcs11_funcs->C_Initialize(NULL);
    if (rc != CKR_OK && rc != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        warnx("C_Initialize failed: 0x%lX: %s", rc, p11_get_ckr(rc));
        goto done;
    }

    p11tool_pkcs11_initialized = true;

    rc = p11tool_open_pkcs11_session(slot, command->session_flags |
                                                (so ? CKF_RW_SESSION : 0),
                                     pin, so ? CKU_SO : CKU_USER,
                                     known_tokens);
    if (rc != CKR_OK)
        goto done;

done:
    pin_free(&buf_user_pin);

    return rc;
}

void p11tool_term_pkcs11(void)
{
    CK_RV rc;

    if (p11tool_pkcs11_session != CK_INVALID_HANDLE)
        p11tool_close_pkcs11_session();

    if (p11tool_pkcs11_funcs != NULL && p11tool_pkcs11_initialized) {
        rc = p11tool_pkcs11_funcs->C_Finalize(NULL);
        if (rc != CKR_OK)
            warnx("C_Finalize failed: 0x%lX: %s", rc, p11_get_ckr(rc));
    }

#ifndef WITH_SANITIZER
    if (p11tool_pkcs11_lib != NULL)
        dlclose(p11tool_pkcs11_lib);
#endif

    p11tool_pkcs11_lib = NULL;
    p11tool_pkcs11_funcs = NULL;

    if (p11tool_pin != NULL) {
        OPENSSL_cleanse(p11tool_pin,  strlen(p11tool_pin));
        free(p11tool_pin);
    }
}

bool p11tool_is_rejected_by_policy(CK_RV ret_code, CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info;
    CK_RV rc;

    if (ret_code != CKR_FUNCTION_FAILED)
        return false;

    rc = p11tool_pkcs11_funcs->C_GetSessionInfo(session, &info);
    if (rc != CKR_OK) {
        warnx("C_GetSessionInfo failed: 0x%lX: %s", rc, p11_get_ckr(rc));
        return false;
    }

    return (info.ulDeviceError == CKR_POLICY_VIOLATION);
}

CK_RV p11tool_check_wrap_mech_supported(CK_SLOT_ID slot,
                                        CK_MECHANISM_TYPE mechanism,
                                        CK_BBOOL wrap, CK_BBOOL unwrap)
{
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    rc = p11tool_pkcs11_funcs->C_GetMechanismInfo(slot, mechanism, &mech_info);
    if (rc != CKR_OK) {
        warnx("Token in slot %lu does not support mechanism %s", slot,
              p11_get_ckm(&mechtable_funcs, mechanism));
        return rc;
    }

    if (wrap && (mech_info.flags & CKF_WRAP) == 0) {
        warnx("Mechanism %s does not support to wrap keys",
              p11_get_ckm(&mechtable_funcs, mechanism));
        return CKR_MECHANISM_INVALID;
    }

    if (unwrap && (mech_info.flags & CKF_UNWRAP) == 0) {
        warnx("Mechanism %s does not support to unwrap keys",
              p11_get_ckm(&mechtable_funcs, mechanism));
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

CK_RV p11tool_check_keygen_mech_supported(CK_SLOT_ID slot,
                                          CK_MECHANISM_TYPE mechanism,
                                          bool is_asymmetric, CK_ULONG keysize)
{
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    rc = p11tool_pkcs11_funcs->C_GetMechanismInfo(slot, mechanism, &mech_info);
    if (rc != CKR_OK) {
        warnx("Token in slot %lu does not support mechanism %s", slot,
              p11_get_ckm(&mechtable_funcs, mechanism));
        return rc;
    }

    if ((mech_info.flags & (is_asymmetric ?
                                CKF_GENERATE_KEY_PAIR : CKF_GENERATE)) == 0) {
        warnx("Mechanism %s does not support to generate keys",
              p11_get_ckm(&mechtable_funcs, mechanism));
        return CKR_MECHANISM_INVALID;
    }

    if (keysize != 0 &&
        mech_info.ulMinKeySize != 0 && mech_info.ulMaxKeySize != 0) {
        if (keysize < mech_info.ulMinKeySize ||
            keysize > mech_info.ulMaxKeySize) {
            warnx("Mechanism %s does not support to generate keys of size %lu",
                  p11_get_ckm(&mechtable_funcs, mechanism),
                  keysize);
            return CKR_KEY_SIZE_RANGE;
        }
    }

    return CKR_OK;
}

char p11tool_prompt_user(const char *message, char* allowed_chars)
{
    int len;
    size_t linelen = 0;
    char *line = NULL;
    char ch = '\0';

    printf("%s", message);

    while (1) {
        len = getline(&line, &linelen, stdin);
        if (len == -1)
            break;

        if (strlen(line) == 2 && strpbrk(line, allowed_chars) != 0) {
            ch = line[0];
            break;
        }

        warnx("Improper reply, try again");
    }

    if (line != NULL)
        free(line);

    return ch;
}

int p11tool_pem_password_cb(char *buf, int size, int rwflag, void *userdata)
{
    struct p11tool_pem_password_cb_data *data = userdata;
    const char *pem_password = data->pem_password;
    char *buf_pem_password = NULL;
    char *msg = NULL;
    int len;

    UNUSED(rwflag);
    UNUSED(userdata);

    if (pem_password == NULL)
        pem_password = getenv(data->env_var_name);

    if (data->force_prompt || pem_password == NULL) {
        if (asprintf(&msg, "Please enter PEM password for '%s': ",
                     data->pem_file_name) <= 0) {
            warnx("Failed to allocate memory for message");
            return -1;
        }
        pem_password = pin_prompt(&buf_pem_password, msg);
        free(msg);
        if (pem_password == NULL) {
            warnx("Failed to prompt for PEM password");
            return -1;
        }
    }

    len = strlen(pem_password);
    if (len > size) {
        warnx("PEM password is too long");
        return -1;
    }

    strncpy(buf, pem_password, size);

    pin_free(&buf_pem_password);

    return len;
}

CK_RV p11tool_ASN1_TIME2date(const ASN1_TIME *asn1time, CK_DATE *date)
{
    struct tm time;
    char tmp[40];

    if (!ASN1_TIME_to_tm(asn1time, &time)) {
        warnx("ASN1_TIME_to_tm failed to convert the certificate's date");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    snprintf(tmp, sizeof(tmp), "%04d%02d%02d",
             time.tm_year + 1900, time.tm_mon + 1, time.tm_mday);
    memcpy(date->year, tmp, 4);
    memcpy(date->month, tmp + 4, 2);
    memcpy(date->day, tmp + 4 + 2, 2);

    return CKR_OK;
}

#if OPENSSL_VERSION_PREREQ(3, 0)
CK_RV p11tool_get_octet_string_param_from_pkey(EVP_PKEY *pkey,
                                               const char *param,
                                               CK_BYTE **key, size_t *key_len)
{
    if (EVP_PKEY_get_octet_string_param(pkey, param, NULL, 0, key_len) != 1 ||
        *key_len == OSSL_PARAM_UNMODIFIED) {
        warnx("EVP_PKEY_get_octet_string_param failed for '%s'\n", param);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    *key = calloc(1, *key_len);
    if (*key == NULL) {
        warnx("Failed to allocate buffer for '%s'\n", param);
        return CKR_HOST_MEMORY;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, param,
                                        *key, *key_len, key_len) != 1) {
        warnx("EVP_PKEY_get_octet_string_param failed for '%s'\n", param);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}
#endif

CK_RV p11tool_prepare_uri(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS *class,
                          const struct p11tool_objtype *objtype,
                          const char *typestr, const char* label,
                          bool detailed_uri, CK_SLOT_ID slot,
                          struct p11_uri **uri)
{
    struct p11_uri *u;
    CK_RV rc;

    u = p11_uri_new();
    if (u == NULL) {
        warnx("Failed to allocate URI for %s %s \"%s\"", typestr, objtype->obj_typestr, label);
        return CKR_HOST_MEMORY;
    }

    if (detailed_uri) {
        /* include library and slot information only in detailed URIs */
        u->info = &p11tool_pkcs11_info;
        u->slot_id = slot;
        u->slot_info = &p11tool_pkcs11_slotinfo;
    }
    u->token_info = &p11tool_pkcs11_tokeninfo;

    u->obj_class[0].ulValueLen = sizeof(*class);
    u->obj_class[0].pValue = class;

    u->obj_label[0].ulValueLen = label != NULL ? strlen(label) : 0;
    u->obj_label[0].pValue = (char *)label;

    rc = p11tool_get_attribute(key, &u->obj_id[0]);
    if (rc != CKR_OK) {
        warnx("Failed to get CKA_ID for %s %s \"%s\": 0x%lX: %s",
              typestr, objtype->obj_typestr, label, rc, p11_get_ckr(rc));
        if (u->obj_id[0].pValue != NULL)
            free(u->obj_id[0].pValue);
        p11_uri_free(u);
        return rc;
    }

    *uri = u;

    return CKR_OK;
}

CK_RV p11tool_bio_readall(BIO *bio, CK_BYTE **buffer, CK_ULONG *read_len)
{
    CK_ULONG ofs = 0, buf_len = 0;
    CK_BYTE *buf = NULL, *tmp;
    size_t read, left = 0;
    int ret;

    *buffer = NULL;
    *read_len = 0;

    do {
        if (left == 0) {
            buf_len += 1024;

            tmp = OPENSSL_realloc(buf, buf_len);
            if (tmp == NULL) {
                warnx("Failed to allocate a buffer for reading a file");
                free(buf);
                return CKR_HOST_MEMORY;
            }
            buf = tmp;
            left = 1024;
        }

        ret = BIO_read_ex(bio, buf + ofs, left, &read);
        if (ret != 1)
            break;

        ofs += read;
        left -= read;
    } while(1);

    if (ofs == 0) {
        free(buf);
        return CKR_FUNCTION_FAILED;
    }

    *buffer = buf;
    *read_len = ofs;

    return CKR_OK;
}

CK_RV p11tool_split_by_delim(char *str, char *delim, char ***list)
{
    char **l = NULL, **tmp;
    CK_ULONG num = 0, left = 0, ofs = 0;
    char *tok;
    char *save = NULL;

    do {
        tok = strtok_r(save == NULL ? str : NULL, delim, &save);

        if (left == 0) {
            num += 16;

            tmp = realloc(l, num * sizeof(char *));
            if (tmp == NULL) {
                warnx("Failed to allocate a buffer for reading a file");
                free(l);
                return CKR_HOST_MEMORY;
            }

            l = tmp;
            left = 16;
        }

        l[ofs] = tok;
        ofs++;
        left--;
    } while(tok != NULL);

    *list = l;

    return CKR_OK;
}
