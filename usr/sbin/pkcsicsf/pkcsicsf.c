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
#include <string.h>
#include <grp.h>
#include <openssl/crypto.h>

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

static int secure_racf_passwd(const char *racfpwd, CK_ULONG len,
                              const struct icsf_token_record *token);

static void usage(char *progname)
{
    printf("usage:\t%s [-h] [ -l | -a token-name] [-b BINDDN]"
           " [-c client-cert-file] [-C CA-cert-file] [-k key] [-u URI]"
           " [-m MECHANISM]\n", progname);
    printf("\t-a add specified token\n");
    printf("\t-b the distinguish name to bind for simple mode\n");
    printf("\t-C the CA certificate file for SASL mode\n");
    printf("\t-c the client certificate file for SASL mode\n");
    printf("\t-h show this help\n");
    printf("\t-k the client private key file for SASL mode\n");
    printf("\t-l list available tokens\n");
    printf("\t-m the authentication mechanism, "
           "it can be 'simple' or 'sasl'\n");
    printf("\t-u the URI to connect to\n");

    exit(-1);
}

static int get_free_slot(struct ConfigBaseNode *config)
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

static int config_add_slotinfo(int num_of_slots,
                               struct icsf_token_record *tokens)
{
    int slot_id = -1;
    char configname[LINESIZ];
    struct ConfigBaseNode *config = NULL;
    struct ConfigIdxStructNode *slot;
    struct ConfigBareValNode *stdll_val, *confname_val, *tokname_val;
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
        /* get the slot for next entry */
        slot_id = get_free_slot(config);
        if (slot_id == -1) {
            fprintf(stderr, "No more free slot found\n");
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

        if (slot == NULL || stdll_val == NULL || confname_val == NULL ||
            tokname_val == NULL || eoc1 == NULL || eoc2 == NULL ||
            eoc3 == NULL) {
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
            confignode_freeeoc(eoc3);
            confignode_deepfree(config);
            return 1;
        }

        confignode_append(slot->value, &stdll_val->base);
        confignode_append(slot->value, &confname_val->base);
        confignode_append(slot->value, &tokname_val->base);
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

static void remove_mk_so_file(const char *tokname)
{
    char fname[PATH_MAX];

    /* remove the so and user files */
    snprintf(fname, sizeof(fname), "%s/%s/MK_SO", CONFIG_PATH, tokname);
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

static int retrieve_all(const char *racfpwd)
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
    rc = config_add_slotinfo(tokenCount, tokens);
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
 * Write an initial NVTOK.DAT for a freshly-added ICSF token so that
 * so_pin_sha reflects the SO PIN used to create MK_SO.
 *
 * Only TOKEN_DATA is written; the ICSF-specific slot_data appendage is
 * omitted and will be written by the stdll on the first save_token_data
 * call (e.g. after pkcsconf -P).  token_specific_load_token_data handles
 * the short-file case gracefully.
 */
static int write_initial_nvtok_dat(const char *tokname, const char *sopin,
                                   size_t sopin_len,
                                   const struct icsf_token_record *token)
{
    char fname[PATH_MAX];
    TOKEN_DATA td;
    unsigned char so_hash[SHA1_HASH_SIZE];
    struct group *grp;
    int fd = -1;
    FILE *fp = NULL;
    int rc = 0;

    if (compute_sha1(sopin, sopin_len, (char *)so_hash) != 0) {
        fprintf(stderr, "Failed to compute SO PIN hash.\n");
        return -1;
    }

    memset(&td, 0, sizeof(td));

    memcpy(td.so_pin_sha, so_hash, SHA1_HASH_SIZE);
    /* user_pin_sha all-zero signals "not yet initialised" to icsftok_login */
    memcpy(td.user_pin_sha, "00000000000000000000", SHA1_HASH_SIZE);

    /*
     * Initial flags: identical to what init_tokenInfo() sets, plus
     * CKF_TOKEN_INITIALIZED (the ICSF token is already provisioned on
     * z/OS - no C_InitToken is required).
     */
    td.token_info.flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_CLOCK_ON_TOKEN |
                          CKF_USER_PIN_TO_BE_CHANGED |
                          CKF_DUAL_CRYPTO_OPERATIONS |
                          CKF_TOKEN_INITIALIZED;

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
    OPENSSL_cleanse(so_hash, sizeof(so_hash));
    /* On failure remove any partially-written file. */
    if (rc != 0)
        unlink(fname);
    return rc;
}

static int secure_racf_passwd(const char *racfpwd, CK_ULONG len,
                              const struct icsf_token_record *token)
{
    const char *tokname = token->name;
    const char *sopin;
    char *buf_so = NULL;
    unsigned char masterkey[AES_KEY_SIZE_256];
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
    if ((get_randombytes(masterkey, AES_KEY_SIZE_256)) != CKR_OK) {
        fprintf(stderr, "Could not generate masterkey.\n");
        rc = -1;
        goto cleanup;
    }

    /* use the master key to secure the racf passwd */
    rc = secure_racf(NULL, (CK_BYTE *)racfpwd, len, masterkey, AES_KEY_SIZE_256,
                     tokname);
    if (rc != 0) {
        fprintf(stderr, "Failed to secure racf passwd.\n");
        rc = -1;
        goto cleanup;
    }

    /* now secure the master key with a derived key */
    /* first get the filename to put the  encrypted masterkey */
    snprintf(fname, sizeof(fname), "%s/%s/MK_SO", CONFIG_PATH, tokname);
    rc = secure_masterkey(NULL, masterkey, AES_KEY_SIZE_256, (CK_BYTE *)sopin,
                          strlen(sopin), fname);

    if (rc != 0) {
        fprintf(stderr, "Failed to secure masterkey.\n");
        /* remove the racf file */
        remove_racf_file(tokname);
        rc = -1;
        goto cleanup;
    }

    /*
     * Write an initial NVTOK.DAT with so_pin_sha matching the PIN just
     * used to create MK_SO. 
     */
    rc = write_initial_nvtok_dat(tokname, sopin, strlen(sopin), token);
    if (rc != 0) {
        fprintf(stderr, "Failed to write initial token data.\n");
        remove_racf_file(tokname);
        remove_mk_so_file(tokname);
        goto cleanup;
    }

cleanup:
    OPENSSL_cleanse(masterkey, sizeof(masterkey));
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

    while ((c = getopt(argc, argv, "hla:b:u:m:k:c:C:")) != (-1)) {
        switch (c) {
        case 'a':
            flags |= CFG_ADD;
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
            if ((cert = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
                goto cleanup;
            }
            break;
        case 'k':
            flags |= CFG_PRIVKEY;
            if ((privkey = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
                goto cleanup;
            }
            break;
        case 'C':
            flags |= CFG_CACERT;
            if ((cacert = strdup(optarg)) == NULL) {
                rc = -1;
                fprintf(stderr, "strdup failed: line %d\n", __LINE__);
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
    if ((!flags) || (!(flags & CFG_ADD) && !(flags & CFG_LIST)))
        usage(argv[0]);

    /* If add, then must specify a mechanism and a name */
    if ((flags & CFG_ADD) && (!(flags & CFG_MECH) || tokenname == NULL))
        usage(argv[0]);

    /* If list, then must specify a mechanism */
    if ((flags & CFG_LIST) && !(flags & CFG_MECH))
        usage(argv[0]);

    /* Cannot add and list at the same time */
    if ((flags & CFG_LIST) && (flags & CFG_ADD))
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

    /* get racf password if needed */
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

            /* bind to ldap server */
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


    /* Add token(s) */
    if (flags & CFG_ADD) {
        if (strcmp(tokenname, "all") == 0) {
            rc = retrieve_all(racfpwd);
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
            rc = config_add_slotinfo(1, &found_token);
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
