/*
 * COPYRIGHT (c) International Business Machines Corp. 2012-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * OpenCryptoki ICSF token configuration tool.
 *
 */

#include "platform.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <string.h>
#include <grp.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "icsf.h"
#include "slotmgr.h"
#include "pbkdf.h"
#include "defs.h"
#include "host_defs.h"
#include "cfgparser.h"
#include "configuration.h"
#include "pin_prompt.h"

#define OCK_TOOL
#include "pkcs_utils.h"

/*
 * KDF purpose strings and iteration counts.
 * These MUST stay identical to SO_KDF_LOGIN_PURPOSE, SO_KDF_WRAP_PURPOSE,
 * USER_KDF_LOGIN_PURPOSE, USER_KDF_WRAP_PURPOSE, and the corresponding _IT
 * values defined in usr/lib/common/h_extern.h.
 * They are duplicated here because h_extern.h declares stdll functions that
 * are not linked into this tool.  If any value changes in h_extern.h it must
 * be updated here too.
 */
#define ICSF_SO_KDF_LOGIN_IT       100000ULL
#define ICSF_SO_KDF_LOGIN_PURPOSE  "so_login_purpose________________"
#define ICSF_SO_KDF_WRAP_IT        100000ULL
#define ICSF_SO_KDF_WRAP_PURPOSE   "so_wrap_purpose_________________"
#define ICSF_USER_KDF_LOGIN_IT     100000ULL
#define ICSF_USER_KDF_LOGIN_PURPOSE "user_login_purpose______________"
#define ICSF_USER_KDF_WRAP_IT      100000ULL
#define ICSF_USER_KDF_WRAP_PURPOSE "user_wrap_purpose_______________"

pkcs_trace_level_t trace_level = TRACE_LEVEL_NONE;

#define CFG_ADD         0x0001
#define CFG_LIST        0x0002
#define CFG_BINDDN      0x0004
#define CFG_CERT        0x0008
#define CFG_PRIVKEY     0x0010
#define CFG_CACERT      0x0020
#define CFG_URI         0x0040
#define CFG_MECH        0x0080
#define CFG_MECH_SASL   0x0100
#define CFG_MECH_SIMPLE 0x0200
#define CFG_CHGPWD      0x0400
#define CFG_SLOT        0x0800

/* Token authentication mechanism values, matching ICSF_CFG_MECH_* in
 * icsf_config.h */
#define TOK_MECH_SIMPLE 0
#define TOK_MECH_SASL   1

#define SALT_SIZE   16
#define SASL    "sasl"
#define SLOT    "slot"

#define TMPSIZ 64
#define LINESIZ 512
#define TOKBUF  2056
#define STDLL   "libpkcs11_icsf.so"

LDAP *ld;
char *binddn = NULL;
char *uri = NULL;
char *mech = NULL;
char *cert = NULL;
char *cacert = NULL;
char *privkey = NULL;
unsigned long flags = 0;
int requested_slot = -1;

static int secure_racf_passwd(const char *racfpwd, CK_ULONG len,
                              const struct icsf_token_record *token);

static void usage(char *progname)
{
    printf("usage:\t%s [-h] [ -l | -a token-name] [-b BINDDN]"
           " [-c client-cert-file] [-C CA-cert-file] [-k key] [-u URI]"
           " [-m MECHANISM] [-s slot]\n", progname);
    printf("      \t%s -p token-name\n", progname);
    printf("\t-a add specified token\n");
    printf("\t-b the distinguish name to bind for simple mode\n");
    printf("\t-C the CA certificate file for SASL mode\n");
    printf("\t-c the client certificate file for SASL mode\n");
    printf("\t-h show this help\n");
    printf("\t-k the client private key file for SASL mode\n");
    printf("\t-l list available tokens\n");
    printf("\t-m the authentication mechanism, "
           "it can be 'simple' or 'sasl'\n");
    printf("\t-p change the RACF password for an existing token\n");
    printf("\t-s the slot number to use when adding a token\n");
    printf("\t-u the URI to connect to\n");

    exit(-1);
}

static int get_free_slot(struct ConfigBaseNode *config, int want_slot)
{
    struct ConfigBaseNode *c;
    struct ConfigIdxStructNode *slot;
    CK_BBOOL slot_used[NUMBER_SLOTS_MANAGED] = { 0 };
    int i;

    confignode_foreach(c, config, i) {
        if (confignode_hastype(c, CT_IDX_STRUCT)) {
            slot = confignode_to_idxstruct(c);
            if (strcmp(slot->base.key, "slot") == 0 &&
                slot->idx < NUMBER_SLOTS_MANAGED)
                slot_used[slot->idx] = CK_TRUE;
        }
    }

    if (want_slot >= 0) {
        if (want_slot >= NUMBER_SLOTS_MANAGED) {
            fprintf(stderr, "Slot number %d exceeds maximum allowed slot "
                    "number %d.\n", want_slot, NUMBER_SLOTS_MANAGED - 1);
            return -1;
        }
        if (slot_used[want_slot] == CK_TRUE) {
            fprintf(stderr, "Slot number %d is already in use.\n", want_slot);
            return -1;
        }
        return want_slot;
    }

    for (i = 0; i < NUMBER_SLOTS_MANAGED; i++) {
        if (slot_used[i] == CK_FALSE)
            return i;
    }

    return -1;
}

static int remove_file(char *filename)
{
    if (unlink(filename) == -1 && errno != ENOENT) {
        fprintf(stderr, "unlink failed for %s, line %d: %s\n",
                filename, __LINE__, strerror(errno));
        return -1;
    }

    return 0;
}

static void add_token_config_entry(struct ConfigIdxStructNode *s, char *key, char *value)
{
    struct ConfigStringValNode *v;

    if (!key || !value)
        return;

    v = confignode_allocstringvaldumpable(key, value, 0, NULL);
    if (v != NULL)
        confignode_append(s->value, &v->base);
}

static int add_token_config(const char *configname,
                            struct icsf_token_record token, int slot)
{
    struct ConfigIdxStructNode *s;
    struct ConfigEOCNode *eoc1, *eoc2;
    FILE *tfp;

    eoc1 = confignode_alloceoc(NULL, 0);
    eoc2 = confignode_alloceoc(NULL, 0);
    s = confignode_allocidxstructdumpable("slot", slot,
                                          (struct ConfigBaseNode *)eoc1,
                                          (struct ConfigBaseNode *)eoc2,
                                          0, NULL);
    if (s == NULL || eoc1 == NULL || eoc2 == NULL) {
        if (s == NULL) {
            confignode_freeeoc(eoc1);
            confignode_freeeoc(eoc2);
        } else {
            confignode_deepfree(&s->base);
        }
        fprintf(stderr, "Failed to add an entry for %s token\n", token.name);
        return -1;
    }

    /* add the info */
    add_token_config_entry(s, "TOKEN_NAME", token.name);
    add_token_config_entry(s, "TOKEN_MANUFACTURE", token.manufacturer);
    add_token_config_entry(s, "TOKEN_MODEL", token.model);
    add_token_config_entry(s, "TOKEN_SERIAL", token.serial);
    add_token_config_entry(s, "MECH", (flags & CFG_MECH_SIMPLE)
                           ? "SIMPLE" : "SASL");

    /* add BIND info */
    if (flags & CFG_MECH_SIMPLE) {
        add_token_config_entry(s, "BINDDN", binddn);
        add_token_config_entry(s, "URI", uri);
    } else {
        add_token_config_entry(s, "URI", uri);
        add_token_config_entry(s, "CERT", cert);
        add_token_config_entry(s, "CACERT", cacert);
        add_token_config_entry(s, "KEY", privkey);
    }

    /* create the token config file */
    tfp = fopen_nofollow(configname, "w");
    if (tfp == NULL) {
        fprintf(stderr, "fopen failed, line %d: %s\n",
                __LINE__, strerror(errno));
        confignode_deepfree(&s->base);
        return -1;
    }

    fchmod(fileno(tfp), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    confignode_dump(tfp, &s->base, NULL, 2);

    fclose(tfp);
    confignode_deepfree(&s->base);

    return 0;
}

static void config_parse_error(int line, int col, const char *msg)
{
    fprintf(stderr, "Error parsing config file: line %d column %d: %s\n", line,
            col, msg);
}

static struct ConfigBaseNode *config_parse(const char *config_file,
                                           CK_BBOOL track_comments)
{
    FILE *file;
    struct ConfigBaseNode *config = NULL;
    int ret;

    file = fopen(config_file, "r");
    if (file == NULL)
        return NULL;

    ret = parse_configlib_file(file, &config, config_parse_error,
                               track_comments);
    fclose(file);
    if (ret != 0)
        return NULL;

    return config;
}

/*
 * read_token_config - find the token config file for @tokname by looking up
 * the 'tokname' + 'confname' keys in opencryptoki.conf, then parse MECH,
 * URI, and BINDDN out of that config file.
 *
 * The confname is stored in opencryptoki.conf (written by pkcsicsf -a).
 * It is NOT stored in NVTOK.DAT: the slot_data appendage that holds it is
 * only written on the first login, so it may not be present.
 * Using opencryptoki.conf is therefore the only reliable path.
 *
 * Returns 0 on success, -1 on error.
 */
static int read_token_config(const char *tokname, int *out_mech,
                              char *out_uri, char *out_dn)
{
    struct ConfigBaseNode *config = NULL, *c, *child;
    struct ConfigIdxStructNode *slot;
    char confname[PATH_MAX] = { 0 };
    char confpath[PATH_MAX];
    char mech_str[64] = { 0 };
    int i, j, found_slot = 0, found_conf = 0;

    *out_uri = '\0';
    *out_dn  = '\0';

    /* Step 1: find the confname for this tokname in opencryptoki.conf */
    config = config_parse(OCK_CONFIG, FALSE);
    if (!config) {
        fprintf(stderr, "Cannot parse config file '%s'.\n", OCK_CONFIG);
        return -1;
    }

    confignode_foreach(c, config, i) {
        char this_tokname[256] = { 0 };
        char this_confname[PATH_MAX] = { 0 };

        if (!confignode_hastype(c, CT_IDX_STRUCT))
            continue;
        slot = confignode_to_idxstruct(c);
        if (strcmp(slot->base.key, "slot") != 0)
            continue;

        confignode_foreach(child, slot->value, j) {
            char *val = confignode_getstr(child);

            if (!val)
                continue;
            if (strcasecmp(child->key, "tokname") == 0)
                strncpy(this_tokname, val, sizeof(this_tokname) - 1);
            else if (strcasecmp(child->key, "confname") == 0)
                strncpy(this_confname, val, sizeof(this_confname) - 1);
        }

        if (strcasecmp(this_tokname, tokname) == 0 &&
            this_confname[0] != '\0') {
            memcpy(confname, this_confname, sizeof(confname));
            found_slot = 1;
            break;
        }
    }
    confignode_deepfree(config);
    config = NULL;

    if (!found_slot) {
        fprintf(stderr,
                "Token '%s' not found in '%s'.\n"
                "Has it been added with pkcsicsf -a?\n",
                tokname, OCK_CONFIG);
        return -1;
    }

    /* Step 2: resolve confname to an absolute path */
    if (confname[0] == '/') {
        if (ock_snprintf(confpath, sizeof(confpath), "%s", confname) != 0) {
            fprintf(stderr, "Token config file path too long: '%s'.\n",
                    confname);
            return -1;
        }
    } else {
        if (ock_snprintf(confpath, sizeof(confpath), "%s/%s",
                         OCK_CONFDIR, confname) != 0) {
            fprintf(stderr, "Token config file path too long: '%s/%s'.\n",
                    OCK_CONFDIR, confname);
            return -1;
        }
    }

    /* Step 3: parse MECH, URI, BINDDN from the token config file */
    config = config_parse(confpath, FALSE);
    if (!config) {
        fprintf(stderr, "Cannot parse token config file '%s'.\n", confpath);
        return -1;
    }

    confignode_foreach(c, config, i) {
        if (!confignode_hastype(c, CT_IDX_STRUCT))
            continue;
        slot = confignode_to_idxstruct(c);
        if (strcmp(slot->base.key, "slot") != 0)
            continue;

        confignode_foreach(child, slot->value, j) {
            char *val = confignode_getstr(child);

            if (!val)
                continue;
            if (strcasecmp(child->key, "MECH") == 0)
                strncpy(mech_str, val, sizeof(mech_str) - 1);
            else if (strcasecmp(child->key, "URI") == 0)
                strncpy(out_uri, val, PATH_MAX - 1);
            else if (strcasecmp(child->key, "BINDDN") == 0)
                strncpy(out_dn, val, NAME_MAX - 1);
        }
        found_conf = 1;
        break;
    }
    confignode_deepfree(config);

    if (!found_conf) {
        fprintf(stderr, "No slot entry found in '%s'.\n", confpath);
        return -1;
    }
    if (mech_str[0] == '\0') {
        fprintf(stderr, "No MECH key found in '%s'.\n", confpath);
        return -1;
    }

    if (strcasecmp(mech_str, "SIMPLE") == 0) {
        *out_mech = TOK_MECH_SIMPLE;
    } else if (strcasecmp(mech_str, "SASL") == 0) {
        *out_mech = TOK_MECH_SASL;
    } else {
        fprintf(stderr, "Unknown MECH value '%s' in '%s'.\n",
                mech_str, confpath);
        return -1;
    }

    return 0;
}

static int config_add_slotinfo(int num_of_slots,
                               struct icsf_token_record *tokens,
                               int want_slot)
{
    int slot_id = -1;
    char configname[LINESIZ];
    struct ConfigBaseNode *config = NULL;
    struct ConfigIdxStructNode *slot;
    struct ConfigBareValNode *stdll_val, *confname_val, *tokname_val;
    struct ConfigVersionValNode *tokversion_val;
    struct ConfigEOCNode *eoc1, *eoc2, *eoc3;
    FILE *fp = NULL;
    int i, rc;

    config = config_parse(OCK_CONFIG, TRUE);
    if (config == NULL) {
        fprintf(stderr, "failed to parse config file %s\n", OCK_CONFIG);
        return 1;
    }

    /* For each token in the list do,
     *      - Create a slot entry in ock config file that contains
     *        the stdll and token config name.
     *      - Create a token config file that contains the token info
     *        from the ICSF and the BIND authentication info.
     */
    for (i = 0; i < num_of_slots; i++) {
        /* get the slot for next entry; for the "all" case each successive
         * token gets the next free slot after the explicitly requested one
         * (or after auto-selected ones). */
        slot_id = get_free_slot(config, (i == 0) ? want_slot : -1);
        if (slot_id == -1) {
            if (i > 0 || want_slot < 0)
                fprintf(stderr, "No more free slot found\n");
            /* else: specific error already printed by get_free_slot */
            confignode_deepfree(config);
            return 1;
        }

        if (strcmp(tokens[i].name, "HSM_MK_CHANGE") == 0) {
            fprintf(stderr, "Token name can not be 'HSM_MK_CHANGE'.\n");
            confignode_deepfree(config);
            return 1;
        }

        if (!is_valid_filename_component(tokens[i].name)) {
            fprintf(stderr, "Token name '%s' is not valid (must not be empty, "
                    "must not be '.' or '..', and must not contain '/').\n",
                    tokens[i].name);
            confignode_deepfree(config);
            return 1;
        }

        /* create the config file path and the relative name for the config */
        memset(configname, 0, sizeof(configname));
        snprintf(configname, sizeof(configname), "%s/%s.conf",
                 OCK_CONFDIR, tokens[i].name);

        /* write the token info to the token's config file */
        rc = add_token_config(configname, tokens[i], slot_id);
        if (rc == -1) {
            fprintf(stderr, "failed to add %s token.\n", tokens[i].name);
            confignode_deepfree(config);
            return 1;
        }

        /* add the slot entry to the ock config file */
        eoc1 = confignode_alloceoc(NULL, 0);
        eoc2 = confignode_alloceoc(NULL, 0);
        eoc3 = confignode_alloceoc(NULL, 0);
        slot = confignode_allocidxstructdumpable("slot", slot_id,
                                                 (struct ConfigBaseNode *)eoc1,
                                                 (struct ConfigBaseNode *)eoc2,
                                                 0, NULL);
        stdll_val = confignode_allocbarevaldumpable("stdll", STDLL, 0, NULL);
        confname_val = confignode_allocbarevaldumpable("confname",
                                                       strrchr(configname, '/') + 1,
                                                       0, NULL);
        tokname_val = confignode_allocbarevaldumpable("tokname", tokens[i].name,
                                                       0, NULL);
        tokversion_val = confignode_allocversionvaldumpable("tokversion",
                                                             0x0003001c, 0, NULL);

        if (slot == NULL || stdll_val == NULL || confname_val == NULL ||
            tokname_val == NULL || tokversion_val == NULL ||
            eoc1 == NULL || eoc2 == NULL || eoc3 == NULL) {
            fprintf(stderr, "Failed to add an entry for %s token: %s\n",
                    tokens[i].name, strerror(errno));
            remove_file(configname);
            if (slot == NULL) {
                confignode_freeeoc(eoc1);
                confignode_freeeoc(eoc2);
            }
            confignode_freeidxstruct(slot);
            confignode_freebareval(stdll_val);
            confignode_freebareval(confname_val);
            confignode_freebareval(tokname_val);
            confignode_freeversionval(tokversion_val);
            confignode_freeeoc(eoc3);
            confignode_deepfree(config);
            return 1;
        }

        confignode_append(slot->value, &stdll_val->base);
        confignode_append(slot->value, &confname_val->base);
        confignode_append(slot->value, &tokname_val->base);
        confignode_append(slot->value, &tokversion_val->base);
        confignode_append(config, &eoc3->base);
        confignode_append(config, &slot->base);
    }

    /* Open conf file for write */
    fp = fopen_nofollow(OCK_CONFIG, "w");
    if (!fp) {
        fprintf(stderr, "fopen(%s) failed, errno=%s\n", OCK_CONFIG,
                strerror(errno));
        confignode_deepfree(config);
        return -1;
    }

    fchmod(fileno(fp), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    confignode_dump(fp, config, NULL, 2);
    fclose(fp);

    confignode_deepfree(config);

    return 0;
}

static int list_tokens(void)
{
    size_t i, tokenCount;
    struct icsf_token_record *previous = NULL;
    struct icsf_token_record tokens[MAX_RECORDS];
    int rc, num_seen = 0;

    do {
        tokenCount = MAX_RECORDS;
        /* get the token list from remote z/OS host */
        rc = icsf_list_tokens(ld, NULL, previous, tokens, &tokenCount);
        if (ICSF_RC_IS_ERROR(rc))
            return -1;

        for (i = 0; i < tokenCount; i++) {
            printf("Token #:      %d\n"
                   "Token name:   %s\n"
                   "Manufacturer: %s\n"
                   "Model:        %s\n"
                   "Serial:       %s\n"
                   "Read-only:    %s\n\n",
                   num_seen, tokens[i].name,
                   tokens[i].manufacturer,
                   tokens[i].model, tokens[i].serial,
                   ICSF_IS_TOKEN_READ_ONLY(tokens[i].flags) ? "yes" : "no");
            num_seen++;
        }

        if (tokenCount)
            previous = &tokens[tokenCount - 1];

    } while (tokenCount);

    return 0;
}

static int lookup_name(char *name, struct icsf_token_record *found)
{
    size_t i, tokenCount;
    struct icsf_token_record *previous = NULL;
    struct icsf_token_record tokens[MAX_RECORDS];
    int rc;

    do {
        tokenCount = MAX_RECORDS;
        /* get the token list from remote z/OS host */
        rc = icsf_list_tokens(ld, NULL, previous, tokens, &tokenCount);
        if (ICSF_RC_IS_ERROR(rc)) {
            fprintf(stderr, "Could not get list of tokens.\n");
            memset(found, 0, sizeof(*found));
            return -1;
        }

        for (i = 0; i < tokenCount; i++) {
            if (strncasecmp(name, tokens[i].name,
                            sizeof(tokens[i].name)) == 0) {
                memcpy(found, &tokens[i], sizeof(struct icsf_token_record));
                return 0;
            }
        }
        if (tokenCount)
            previous = &tokens[tokenCount - 1];

    } while (tokenCount);

    /* if we get here, we could not find the token in the list. */
    memset(found, 0, sizeof(*found));

    return -1;
}

static void remove_racf_file(const char *tokname)
{
    char fname[PATH_MAX];

    /* remove the so and user files */
    snprintf(fname, sizeof(fname), "%s/%s/%s", CONFIG_PATH, tokname, RACFFILE);
    remove_file(fname);
}

static int create_directory(const char *parent_dir, const char *tokname)
{
    char fname[PATH_MAX];
    struct group *grp;
    int dfd;

    grp = getgrnam(PKCS_GROUP);
    if (grp == NULL) {
        fprintf(stderr, "getgrname(%s): %s\n", PKCS_GROUP, strerror(errno));
        return -1;
    }

    snprintf(fname, sizeof(fname), "%s/%s", parent_dir, tokname);
    if (mkdir(fname, S_IRWXU | S_IRWXG) != 0) {
        if (errno == EEXIST)
            return 0;
        fprintf(stderr, "Failed to create token directory '%s': %s\n",
                fname, strerror(errno));
        return -1;
    }

    dfd = open_nofollow(fname, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        fprintf(stderr, "Failed to open token directory '%s': %s\n",
                fname, strerror(errno));
        rmdir(fname);
        return -1;
    }

    /* set ownership to euid, and token group */
    if (fchown(dfd, geteuid(), grp->gr_gid) != 0) {
        fprintf(stderr, "Failed to set owner:group ownership on '%s' "
                "directory\n", fname);
        close(dfd);
        rmdir(fname);
        return -1;
    }

    /* mkdir does not set group permission right, set explicitly here */
    if (fchmod(dfd, S_IRWXU | S_IRWXG) != 0) {
        fprintf(stderr, "Failed to change permissions on '%s' directory\n",
                fname);
        close(dfd);
        rmdir(fname);
        return -1;
    }

    close(dfd);
    return 0;
}

static int retrieve_all(const char *racfpwd, int want_slot)
{
    size_t tokenCount, i;
    struct icsf_token_record *previous = NULL;
    struct icsf_token_record tokens[MAX_RECORDS];
    int rc;

    tokenCount = MAX_RECORDS;
    rc = icsf_list_tokens(ld, NULL, previous, tokens, &tokenCount);
    if (ICSF_RC_IS_ERROR(rc)) {
        fprintf(stderr, "Could not get list of tokens.\n");
        return -1;
    }

    /* add slot and token entry(ies) */
    rc = config_add_slotinfo(tokenCount, tokens, want_slot);
    if (rc) {
        fprintf(stderr, "Could not add list of tokens.\n");
        return -1;
    }

    if (flags & CFG_MECH_SIMPLE) {
        /* when using simple auth, secure racf passwd. */
        for (i = 0; i < tokenCount; i++) {
            rc = secure_racf_passwd(racfpwd, strlen(racfpwd), &tokens[i]);
            if (rc != 0)
                return rc;
        }
    }

    return 0;
}

/*
 * Write an initial NVTOK.DAT for a freshly-added ICSF token using the new
 * FIPS-compliant format (tokversion = 3.28, i.e. 0x0003001c).
 *
 * TOKEN_DATA_VERSION is populated with PBKDF2-SHA512 SO login/wrap parameters
 * derived from the SO PIN.  The derived SO wrap key is returned in
 * *out_so_wrap_key so the caller can pass it to secure_masterkey_v3().
 *
 * Only TOKEN_DATA is written; the ICSF-specific slot_data appendage is
 * omitted and will be written by the stdll on the first save_token_data
 * call (e.g. after pkcsconf -P).  token_specific_load_token_data handles
 * the short-file case gracefully.
 */
static int write_initial_nvtok_dat(const char *tokname, const char *sopin,
                                   size_t sopin_len,
                                   const struct icsf_token_record *token,
                                   unsigned char out_so_wrap_key[32])
{
    char fname[PATH_MAX];
    TOKEN_DATA td;
    TOKEN_DATA_VERSION *dat = &td.dat;
    struct group *grp;
    int fd = -1;
    FILE *fp = NULL;
    int rc = 0;

    memset(&td, 0, sizeof(td));

    /* Version 3.28 = 0x0003001c */
    dat->version = 0x0003001c;

    /* SO login key - PBKDF2(sopin, purpose_salt || random32, 100000, SHA-512, 32) */
    dat->so_login_it = ICSF_SO_KDF_LOGIN_IT;
    memcpy(dat->so_login_salt, ICSF_SO_KDF_LOGIN_PURPOSE, 32);
    if (local_rng(dat->so_login_salt + 32, 32) != CKR_OK) {
        fprintf(stderr, "Failed to generate SO login salt.\n");
        rc = -1;
        goto done;
    }
    if (PKCS5_PBKDF2_HMAC(sopin, (int)sopin_len,
                           dat->so_login_salt, 64,
                           (int)dat->so_login_it, EVP_sha512(),
                           32, dat->so_login_key) != 1) {
        fprintf(stderr, "PBKDF2 for SO login key failed.\n");
        rc = -1;
        goto done;
    }

    /* SO wrap key */
    dat->so_wrap_it = ICSF_SO_KDF_WRAP_IT;
    memcpy(dat->so_wrap_salt, ICSF_SO_KDF_WRAP_PURPOSE, 32);
    if (local_rng(dat->so_wrap_salt + 32, 32) != CKR_OK) {
        fprintf(stderr, "Failed to generate SO wrap salt.\n");
        rc = -1;
        goto done;
    }
    if (PKCS5_PBKDF2_HMAC(sopin, (int)sopin_len,
                           dat->so_wrap_salt, 64,
                           (int)dat->so_wrap_it, EVP_sha512(),
                           32, out_so_wrap_key) != 1) {
        fprintf(stderr, "PBKDF2 for SO wrap key failed.\n");
        rc = -1;
        goto done;
    }

    /*
     * User login/wrap keys are left all-zero; all-zero user_login_key
     * signals "user PIN not yet initialised" in icsftok_login().
     * The user KDF params (salts and iteration counts) must still be
     * set so that icsftok_init_pin() can derive keys against them.
     */
    dat->user_login_it = ICSF_USER_KDF_LOGIN_IT;
    memcpy(dat->user_login_salt, ICSF_USER_KDF_LOGIN_PURPOSE, 32);
    if (local_rng(dat->user_login_salt + 32, 32) != CKR_OK) {
        fprintf(stderr, "Failed to generate user login salt.\n");
        rc = -1;
        goto done;
    }
    dat->user_wrap_it = ICSF_USER_KDF_WRAP_IT;
    memcpy(dat->user_wrap_salt, ICSF_USER_KDF_WRAP_PURPOSE, 32);
    if (local_rng(dat->user_wrap_salt + 32, 32) != CKR_OK) {
        fprintf(stderr, "Failed to generate user wrap salt.\n");
        rc = -1;
        goto done;
    }

    /*
     * Initial flags: identical to what init_tokenInfo() sets, plus
     * CKF_TOKEN_INITIALIZED (the ICSF token is already provisioned on
     * z/OS - no C_InitToken is required).
     */
    td.token_info.flags = htobe32(CKF_RNG | CKF_LOGIN_REQUIRED |
                                  CKF_CLOCK_ON_TOKEN |
                                  CKF_USER_PIN_TO_BE_CHANGED |
                                  CKF_DUAL_CRYPTO_OPERATIONS |
                                  CKF_TOKEN_INITIALIZED);

    memset(td.token_info.label, ' ', sizeof(td.token_info.label));
    memcpy(td.token_info.label, token->name,
           MIN(strlen(token->name), sizeof(td.token_info.label)));
    memset(td.token_info.manufacturerID, ' ',
           sizeof(td.token_info.manufacturerID));
    memcpy(td.token_info.manufacturerID, token->manufacturer,
           MIN(strlen(token->manufacturer),
               sizeof(td.token_info.manufacturerID)));
    memset(td.token_info.model, ' ', sizeof(td.token_info.model));
    memcpy(td.token_info.model, token->model,
           MIN(strlen(token->model), sizeof(td.token_info.model)));
    memset(td.token_info.serialNumber, ' ', sizeof(td.token_info.serialNumber));
    memcpy(td.token_info.serialNumber, token->serial,
           MIN(strlen(token->serial), sizeof(td.token_info.serialNumber)));

    /* Byte-swap the TOKEN_DATA_VERSION integer fields for on-disk big-endian */
    dat->version    = htobe32(dat->version);
    dat->so_login_it  = htobe64(dat->so_login_it);
    dat->user_login_it = htobe64(dat->user_login_it);
    dat->so_wrap_it   = htobe64(dat->so_wrap_it);
    dat->user_wrap_it  = htobe64(dat->user_wrap_it);

    grp = getgrnam(PKCS_GROUP);
    if (!grp) {
        fprintf(stderr, "getgrnam(%s): %s\n", PKCS_GROUP, strerror(errno));
        rc = -1;
        goto done;
    }

    snprintf(fname, sizeof(fname), "%s/%s/" PK_LITE_NV, CONFIG_PATH, tokname);

    fd = open_nofollow(fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            rc = 0;
            goto done;
        }
        fprintf(stderr, "open(%s): %s\n", fname, strerror(errno));
        rc = -1;
        goto done;
    }

    if (fchown(fd, geteuid(), grp->gr_gid) != 0 ||
        fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP) != 0) {
        fprintf(stderr, "Failed to set permissions on %s: %s\n",
                fname, strerror(errno));
        rc = -1;
        goto done;
    }

    fp = fdopen(fd, "w");
    if (!fp) {
        fprintf(stderr, "fdopen(%s): %s\n", fname, strerror(errno));
        rc = -1;
        goto done;
    }
    fd = -1; /* fp now owns the fd */

    if (fwrite(&td, sizeof(td), 1, fp) != 1) {
        fprintf(stderr, "fwrite(%s): %s\n", fname, strerror(errno));
        rc = -1;
    }

done:
    if (fp)
        fclose(fp);
    else if (fd >= 0)
        close(fd);
    /* On failure remove any partially-written file. */
    if (rc != 0)
        unlink(fname);
    OPENSSL_cleanse(&td, sizeof(td));
    return rc;
}

static int secure_racf_passwd(const char *racfpwd, CK_ULONG len,
                              const struct icsf_token_record *token)
{
    const char *tokname = token->name;
    const char *sopin;
    char *buf_so = NULL;
    unsigned char masterkey[AES_KEY_SIZE_256];
    unsigned char so_wrap_key[32];
    char fname[PATH_MAX];
    char msg[PATH_MAX];
    int rc;

    if (!is_valid_filename_component(tokname)) {
        fprintf(stderr, "Token name '%s' is not valid (must not be empty, "
                "must not be '.' or '..', and must not contain '/').\n",
                tokname);
        return -1;
    }

    /* Create the token directory, if not already existent */
    if (create_directory(CONFIG_PATH, tokname) != 0) {
        rc = -1;
        goto cleanup;
    }

    /* Create the lock directory, if not already existent */
    if (create_directory(LOCKDIR_PATH, tokname) != 0) {
        rc = -1;
        goto cleanup;
    }

    /* get the SO PIN */
    snprintf(msg, sizeof(msg), "Enter the SO PIN for token '%s': ", tokname);
    sopin = pin_prompt(&buf_so, msg);
    if (!sopin) {
        fprintf(stderr, "Could not get SO PIN.\n");
        rc = -1;
        goto cleanup;
    }

    /* generate a masterkey */
    if (local_rng(masterkey, AES_KEY_SIZE_256) != CKR_OK) {
        fprintf(stderr, "Could not generate masterkey.\n");
        rc = -1;
        goto cleanup;
    }

    /* use the master key to secure the RACF passwd (new v3 GCM format) */
    rc = (int)secure_racf_v3(NULL, (CK_BYTE *)racfpwd, len, masterkey, tokname);
    if (rc != 0) {
        fprintf(stderr, "Failed to secure racf passwd.\n");
        rc = -1;
        goto cleanup;
    }

    /*
     * Write an initial NVTOK.DAT in new FIPS-compliant format.
     * The function also returns the derived SO wrap key that we
     * need to protect MK_SO.
     */
    rc = write_initial_nvtok_dat(tokname, sopin, strlen(sopin), token,
                                 so_wrap_key);
    if (rc != 0) {
        fprintf(stderr, "Failed to write initial token data.\n");
        remove_racf_file(tokname);
        goto cleanup;
    }

    /* Protect the master key with AES-256-KW under the SO wrap key */
    snprintf(fname, sizeof(fname), "%s/%s/MK_SO", CONFIG_PATH, tokname);
    rc = secure_masterkey_v3(NULL, masterkey, so_wrap_key, fname);
    if (rc != 0) {
        char nvtok[PATH_MAX];

        fprintf(stderr, "Failed to secure masterkey.\n");
        remove_racf_file(tokname);
        unlink(fname);  /* remove partial MK_SO if any */
        /* remove NVTOK.DAT */
        snprintf(nvtok, sizeof(nvtok), "%s/%s/" PK_LITE_NV,
                 CONFIG_PATH, tokname);
        unlink(nvtok);
        rc = -1;
        goto cleanup;
    }

cleanup:
    OPENSSL_cleanse(masterkey, sizeof(masterkey));
    OPENSSL_cleanse(so_wrap_key, sizeof(so_wrap_key));
    pin_free(&buf_so);

    return rc;
}

/*
 * change_racf_passwd - update the encrypted RACF password for an existing
 * ICSF token after the RACF password has been changed on the z/OS server.
 *
 * Reads MECH, URI, and BINDDN from the existing token configuration
 * (via opencryptoki.conf + the per-token conf file) so the user does not
 * need to supply -m/-u/-b on the command line.
 * Refuses with a clear error if the token uses SASL authentication, as
 * SASL tokens do not use a RACF password file.
 *
 * Prompts for the new RACF password, verifies it by binding to the LDAP
 * server, then prompts for the SO PIN to unwrap the master key and
 * re-encrypts the RACF file in place.
 *
 * Supports both the v3 token format (tokversion >= 3.28, 40-byte MK_SO)
 * and the legacy format (v1/v2 MK_SO).
 *
 * Steps:
 *   1. Read MECH/URI/BINDDN from opencryptoki.conf + token conf file.
 *   2. Prompt for the new RACF password; verify via icsf_login().
 *   3. Read NVTOK.DAT; verify version and cross-check MK_SO size.
 *   4. Prompt for the SO PIN; unwrap the master key.
 *   5. Re-encrypt the RACF file with the new password and the same master key.
 */
static int change_racf_passwd(const char *tokname)
{
    char nvtok_fname[PATH_MAX];
    char mk_so_fname[PATH_MAX];
    char lockfile[PATH_MAX];
    char tok_uri[PATH_MAX + 1];
    char tok_dn[NAME_MAX + 1];
    TOKEN_DATA td;
    TOKEN_DATA_VERSION *dat = &td.dat;
    uint32_t tok_version;
    struct stat sb;
    int is_v3;
    int tok_mech;
    int lockfd = -1;
    LDAP *chg_ld = NULL;
    const char *racfpwd;
    char *buf_racfpwd = NULL;
    CK_ULONG racflen;
    unsigned char wrap_key[32];
    unsigned char masterkey[AES_KEY_SIZE_256];
    int mk_len = AES_KEY_SIZE_256;
    const char *sopin;
    char *buf_so = NULL;
    char msg[PATH_MAX];
    FILE *fp;
    int rc = -1;
    CK_RV rv;

    if (!is_valid_filename_component(tokname)) {
        fprintf(stderr, "Token name '%s' is not valid.\n", tokname);
        return -1;
    }

    /* Step 1: read authentication config from the existing token config files */
    if (read_token_config(tokname, &tok_mech, tok_uri, tok_dn) != 0)
        return -1;

    if (tok_mech != TOK_MECH_SIMPLE) {
        fprintf(stderr,
                "Token '%s' uses SASL authentication. "
                "SASL tokens do not use a RACF password file; "
                "no update is needed.\n", tokname);
        return -1;
    }

    /* Step 2: prompt for the new RACF password and verify it via LDAP */
    snprintf(msg, sizeof(msg),
             "Enter the new RACF passwd for token '%s': ", tokname);
    racfpwd = pin_prompt(&buf_racfpwd, msg);
    if (!racfpwd) {
        fprintf(stderr, "Could not get RACF passwd.\n");
        goto cleanup;
    }
    racflen = strlen(racfpwd);
    if (racflen >= PIN_SIZE) {
        fprintf(stderr, "RACF passwd too long (max %d characters).\n",
                PIN_SIZE - 1);
        goto cleanup;
    }

    rc = icsf_login(&chg_ld, tok_uri, tok_dn, racfpwd);
    if (rc) {
        fprintf(stderr, "Failed to bind to the LDAP server with the new "
                "RACF password: %s (%d)\n", ldap_err2string(rc), rc);
        rc = -1;
        goto cleanup;
    }
    /* Login succeeded — new password is valid. Close the LDAP session;
     * we do not need it for the local file update that follows. */
    icsf_logout(chg_ld);
    chg_ld = NULL;
    rc = -1; /* reset; success set explicitly below */

    /*
     * Step 3: acquire the token cross-process lock before touching any
     * files in the token data directory.
     */
    snprintf(lockfile, sizeof(lockfile), "%s/%s/LCK..%s",
             LOCKDIR_PATH, tokname, tokname);
    lockfd = open_nofollow(lockfile, OPEN_MODE);
    if (lockfd < 0) {
        fprintf(stderr, "Cannot open lock file %s: %s\n",
                lockfile, strerror(errno));
        goto cleanup;
    }
    if (flock(lockfd, LOCK_EX) != 0) {
        fprintf(stderr, "flock(%s): %s\n", lockfile, strerror(errno));
        goto cleanup;
    }

    /* Step 4: read and validate the token data store (under the lock) */
    snprintf(nvtok_fname, sizeof(nvtok_fname), "%s/%s/" PK_LITE_NV,
             CONFIG_PATH, tokname);
    snprintf(mk_so_fname, sizeof(mk_so_fname), "%s/%s/MK_SO",
             CONFIG_PATH, tokname);

    fp = fopen(nvtok_fname, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open %s: %s\n", nvtok_fname, strerror(errno));
        fprintf(stderr, "Token '%s' does not appear to have been added "
                "with pkcsicsf -a.\n", tokname);
        goto cleanup;
    }
    if (fread(&td, sizeof(td), 1, fp) != 1) {
        fprintf(stderr, "Failed to read %s: %s\n", nvtok_fname, strerror(errno));
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);

    /* TOKEN_DATA_VERSION.version is big-endian on disk */
    tok_version = be32toh(dat->version);
    is_v3 = (tok_version >= 0x0003001cu);

    /* Cross-check: MK_SO file size must agree with the version */
    if (stat(mk_so_fname, &sb) != 0) {
        fprintf(stderr, "Cannot stat %s: %s\n", mk_so_fname, strerror(errno));
        goto cleanup;
    }
    if (is_v3 && sb.st_size != ICSF_MK_FILE_V3_SIZE) {
        fprintf(stderr,
                "NVTOK.DAT reports tokversion 0x%08x (>= 3.28) but MK_SO "
                "has unexpected size %lld (expected %d).\n"
                "The token data store may be corrupted.\n",
                tok_version, (long long)sb.st_size, ICSF_MK_FILE_V3_SIZE);
        goto cleanup;
    }

    /* Release the lock before the interactive SO PIN prompt and the
     * CPU-bound PBKDF2 derivation.  MK_SO is stable at this point:
     * no other pkcsicsf invocation can modify it (only pkcsicsf -a
     * writes MK_SO, and that requires the token to not exist yet).
     * The lock is re-acquired below before writing the RACF file. */
    flock(lockfd, LOCK_UN);
    close(lockfd);
    lockfd = -1;

    /* Step 5: prompt for the SO PIN and unwrap the master key */
    snprintf(msg, sizeof(msg), "Enter the SO PIN for token '%s': ", tokname);
    sopin = pin_prompt(&buf_so, msg);
    if (!sopin) {
        fprintf(stderr, "Could not get SO PIN.\n");
        goto cleanup;
    }

    if (is_v3) {
        /* Byte-swap the on-disk big-endian iteration count before use */
        dat->so_wrap_it = be64toh(dat->so_wrap_it);

        /* Derive the SO wrap key: PBKDF2-SHA-512(sopin, so_wrap_salt, it, 32) */
        if (dat->so_wrap_it > INT_MAX ||
            PKCS5_PBKDF2_HMAC(sopin, (int)strlen(sopin),
                               dat->so_wrap_salt, 64,
                               (int)dat->so_wrap_it, EVP_sha512(),
                               32, wrap_key) != 1) {
            fprintf(stderr, "Failed to derive wrap key from SO PIN.\n");
            goto cleanup;
        }

        rv = get_masterkey_v3(NULL, wrap_key, mk_so_fname, masterkey);
        if (rv != CKR_OK) {
            fprintf(stderr,
                    "Failed to unwrap master key from MK_SO - wrong SO PIN?\n");
            goto cleanup;
        }
    } else {
        /*
         * Legacy format: get_masterkey() reads the salt and format version
         * from MK_SO itself and handles both v1 and v2 KDF variants.
         */
        rv = get_masterkey(NULL, (CK_BYTE *)sopin, (CK_ULONG)strlen(sopin),
                           mk_so_fname, masterkey, &mk_len);
        if (rv != CKR_OK) {
            fprintf(stderr,
                    "Failed to decrypt master key from MK_SO - wrong SO PIN?\n");
            goto cleanup;
        }
    }

    /* Step 6: re-acquire the lock and write the updated RACF file atomically
     * with respect to concurrent stdll readers (getLDAPhandle / reset_token_data
     * both hold XProcLock, which is flock on the same LCK.. file). */
    lockfd = open_nofollow(lockfile, OPEN_MODE);
    if (lockfd < 0) {
        fprintf(stderr, "Cannot re-open lock file %s: %s\n",
                lockfile, strerror(errno));
        goto cleanup;
    }
    if (flock(lockfd, LOCK_EX) != 0) {
        fprintf(stderr, "flock(%s): %s\n", lockfile, strerror(errno));
        goto cleanup;
    }

    if (is_v3) {
        rv = secure_racf_v3(NULL, (const CK_BYTE *)racfpwd, racflen,
                            masterkey, tokname);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to write updated RACF file.\n");
            goto cleanup;
        }
    } else {
        rv = secure_racf(NULL, (CK_BYTE *)racfpwd, racflen,
                         masterkey, (CK_ULONG)mk_len, tokname);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to write updated RACF file.\n");
            goto cleanup;
        }
    }

    printf("RACF password updated successfully for token '%s'.\n", tokname);
    rc = 0;

cleanup:
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    if (chg_ld)
        icsf_logout(chg_ld);
    OPENSSL_cleanse(wrap_key, sizeof(wrap_key));
    OPENSSL_cleanse(masterkey, sizeof(masterkey));
    pin_free(&buf_racfpwd);
    pin_free(&buf_so);
    return rc;
}

int main(int argc, char **argv)
{
    const char *racfpwd = NULL;
    char *buf_racfpwd = NULL;
    char *tokenname = NULL;
    int c;
    int rc = 0;
    struct icsf_token_record found_token;
    char *endptr;
    long val;

    while ((c = getopt(argc, argv, "hla:b:u:m:k:c:C:p:s:")) != (-1)) {
        switch (c) {
        case 'a':
            flags |= CFG_ADD;
            if ((tokenname = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
                goto cleanup;
            }
            break;
        case 'p':
            flags |= CFG_CHGPWD;
            if ((tokenname = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
                goto cleanup;
            }
            break;
        case 'l':
            flags |= CFG_LIST;
            break;
        case 'b':
            flags |= CFG_BINDDN;
            if ((binddn = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
                goto cleanup;
            }
            break;
        case 'c':
            flags |= CFG_CERT;
            cert = realpath(optarg, NULL);
            if (cert == NULL) {
                rc = -1;
                fprintf(stderr, "Cannot resolve path '%s': %s\n",
                        optarg, strerror(errno));
                goto cleanup;
            }
            break;
        case 'k':
            flags |= CFG_PRIVKEY;
            privkey = realpath(optarg, NULL);
            if (privkey == NULL) {
                rc = -1;
                fprintf(stderr, "Cannot resolve path '%s': %s\n",
                        optarg, strerror(errno));
                goto cleanup;
            }
            break;
        case 'C':
            flags |= CFG_CACERT;
            cacert = realpath(optarg, NULL);
            if (cacert == NULL) {
                rc = -1;
                fprintf(stderr, "Cannot resolve path '%s': %s\n",
                        optarg, strerror(errno));
                goto cleanup;
            }
            break;
        case 'u':
            flags |= CFG_URI;
            if ((uri = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
                goto cleanup;
            }
            break;
        case 'm':
            flags |= CFG_MECH;
            if ((mech = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
                goto cleanup;
            }
            if (strcmp(mech, SASL) == 0)
                flags |= CFG_MECH_SASL;
            else
                flags |= CFG_MECH_SIMPLE;
            break;
        case 's':
            errno = 0;
            val = strtol(optarg, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || val < 0 ||
                val >= NUMBER_SLOTS_MANAGED) {
                fprintf(stderr,
                        "Invalid slot number '%s': must be a non-negative "
                        "integer less than %d.\n",
                        optarg, NUMBER_SLOTS_MANAGED);
                rc = -1;
                goto cleanup;
            }
            flags |= CFG_SLOT;
            requested_slot = (int)val;
            break;
        case 'h':
        default:
            usage(argv[0]);
            break;
        }
    }

    /* Noticed that if a user misses an argument after an option,
     * sometimes getopt misses it.
     * For example, pkcsiscf -a -m -b xxxx -u xxxx"
     * To catch these anomalies, check that optind == argc.
     */
    if (optind != argc)
        usage(argv[0]);

    /* If there were no options, print usage. */
    if ((!flags) ||
        (!(flags & CFG_ADD) && !(flags & CFG_LIST) && !(flags & CFG_CHGPWD)))
        usage(argv[0]);

    /* If add, then must specify a mechanism and a name */
    if ((flags & CFG_ADD) && (!(flags & CFG_MECH) || tokenname == NULL))
        usage(argv[0]);

    /* -s is only meaningful with -a */
    if ((flags & CFG_SLOT) && !(flags & CFG_ADD))
        usage(argv[0]);

    /* If list, then must specify a mechanism */
    if ((flags & CFG_LIST) && !(flags & CFG_MECH))
        usage(argv[0]);

    /* If change password, only a token name is required; the mechanism and
     * connection details are read from the existing token configuration.
     * Reject -m/-u/-b/-c/-C/-k to avoid silent mismatches. */
    if ((flags & CFG_CHGPWD) && tokenname == NULL)
        usage(argv[0]);
    if ((flags & CFG_CHGPWD) &&
        (flags & (CFG_MECH | CFG_URI | CFG_BINDDN |
                  CFG_CERT | CFG_PRIVKEY | CFG_CACERT)))
        usage(argv[0]);

    /* Cannot combine operations */
    if (!!(flags & CFG_LIST) + !!(flags & CFG_ADD) +
        !!(flags & CFG_CHGPWD) > 1)
        usage(argv[0]);

    /* May only specify one mechanism */
    if ((flags & CFG_MECH_SASL) && (flags & CFG_MECH_SIMPLE))
        usage(argv[0]);

    /* Cannot specify bind DN with SASL */
    if ((flags & CFG_MECH_SASL) && (flags & CFG_BINDDN))
        usage(argv[0]);

    /* Cannot specify certs or key with SIMPLE */
    if ((flags & CFG_MECH_SIMPLE)
        && (flags & (CFG_CERT | CFG_PRIVKEY | CFG_CACERT)))
        usage(argv[0]);

    if ((flags & CFG_ADD) && geteuid() != 0) {
        fprintf(stderr, "%s can only be used as root.\n", argv[0]);
        exit(-1);
    }

    /* get racf password and bind for -a and -l; -p handles this itself */
    if ((flags & CFG_ADD) || (flags & CFG_LIST)) {
        if (flags & CFG_MECH_SIMPLE) {
            racfpwd = pin_prompt(&buf_racfpwd, "Enter the RACF passwd: ");
            if (!racfpwd) {
                fprintf(stderr, "Could not get RACF passwd.\n");
                rc = -1;
                goto cleanup;
            }
            if (strlen(racfpwd) >= PIN_SIZE) {
                fprintf(stderr, "RACF passwd too long (max %d characters).\n",
                        PIN_SIZE - 1);
                rc = -1;
                goto cleanup;
            }

            rc = icsf_login(&ld, uri, binddn, racfpwd);
        } else {
            rc = icsf_sasl_login(&ld, uri, cert, privkey, cacert, NULL);
        }
        if (rc) {
            fprintf(stderr, "Failed to bind to the ldap server: %s (%d)\n",
                    ldap_err2string(rc), rc);
            goto cleanup;
        }
    }

    /* Change RACF password for an existing token */
    if (flags & CFG_CHGPWD) {
        rc = change_racf_passwd(tokenname);
        goto cleanup;
    }

    /* Add token(s) */
    if (flags & CFG_ADD) {
        if (strcmp(tokenname, "all") == 0) {
            rc = retrieve_all(racfpwd, requested_slot);
            if (rc) {
                fprintf(stderr, "Could not add the list of " "tokens.\n");
                goto cleanup;
            }
        } else {
            /* add only the specified tokenname.
             * first, find it in the list.
             */
            rc = lookup_name(tokenname, &found_token);
            if (rc != 0) {
                fprintf(stderr,
                        "Could not find %s in token list.\n", tokenname);
                rc = -1;
                goto cleanup;
            }

            /* add the entry */
            rc = config_add_slotinfo(1, &found_token, requested_slot);
            if (rc != 0)
                goto cleanup;

            if (flags & CFG_MECH_SIMPLE) {
                /* when using simple auth, secure racf passwd. */
                rc = secure_racf_passwd(racfpwd, strlen(racfpwd), &found_token);
                if (rc != 0)
                    goto cleanup;
            }
        }
    }

    if (flags & CFG_LIST) {
        /* print the list of available tokens */
        rc = list_tokens();
        if (rc != 0)
            fprintf(stderr, "Could not get full list of tokens.\n");
    }

cleanup:
    if (ld)
        icsf_logout(ld);
    if (tokenname)
        free(tokenname);
    if (binddn)
        free(binddn);
    if (cert)
        free(cert);
    if (privkey)
        free(privkey);
    if (cacert)
        free(cacert);
    if (uri)
        free(uri);
    if (mech)
        free(mech);
    pin_free(&buf_racfpwd);

    return rc;
}
