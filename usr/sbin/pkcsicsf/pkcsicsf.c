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

#include "icsf.h"
#include "slotmgr.h"
#include "pbkdf.h"
#include "defs.h"
#include "cfgparser.h"
#include "configuration.h"
#include "pin_prompt.h"

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
    struct stat statbuf;

    /* if file exists, then remove it */
    if ((stat(filename, &statbuf) < 0) && (errno == ENOENT)) {
        if (unlink(filename) == -1) {
            fprintf(stderr, "unlink failed for %s, line %d: %s\n",
                    filename, __LINE__, strerror(errno));
            return -1;
        }
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
        }
        confignode_deepfree(&s->base);
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
    if (strcmp(mech, "simple") == 0) {
        add_token_config_entry(s, "BINDDN", binddn);
        add_token_config_entry(s, "URI", uri);
    } else {
        add_token_config_entry(s, "URI", uri);
        add_token_config_entry(s, "CERT", cert);
        add_token_config_entry(s, "CACERT", cacert);
        add_token_config_entry(s, "KEY", privkey);
    }

    /* create the token config file */
    tfp = fopen(configname, "w");
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
    struct ConfigBareValNode *stdll_val, *confname_val;
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

        /* create the config name using the token's name */
        memset(configname, 0, sizeof(configname));
        snprintf(configname, sizeof(configname), "%s/%s.conf",
                 OCK_CONFDIR, tokens[i].name);

        /* write the token info to the token's config file */
        rc = add_token_config(configname, tokens[i], slot_id);
        if (rc == -1) {
            fprintf(stderr, "failed to add %s token.\n", tokens[i].name);
            /* skip adding this entry */
            continue;
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
        confname_val = confignode_allocbarevaldumpable("confname", configname,
                                                       0, NULL);

        if (slot == NULL || stdll_val == NULL || confname_val == NULL ||
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
            confignode_freeeoc(eoc3);
            continue;
        }

        confignode_append(slot->value, &stdll_val->base);
        confignode_append(slot->value, &confname_val->base);
        confignode_append(config, &eoc3->base);
        confignode_append(config, &slot->base);
    }

    /* Open conf file for write */
    fp = fopen(OCK_CONFIG, "w");
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
    size_t i, tokenCount = MAX_RECORDS;
    struct icsf_token_record *previous = NULL;
    struct icsf_token_record tokens[MAX_RECORDS];
    int rc, num_seen = 0;

    do {
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
    size_t i, tokenCount = MAX_RECORDS;
    struct icsf_token_record *previous = NULL;
    struct icsf_token_record tokens[MAX_RECORDS];
    int rc;

    do {
        /* get the token list from remote z/OS host */
        rc = icsf_list_tokens(ld, NULL, previous, tokens, &tokenCount);
        if (ICSF_RC_IS_ERROR(rc)) {
            fprintf(stderr, "Could not get list of tokens.\n");
            found = NULL;
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
    found = NULL;

    return -1;
}

static void remove_racf_file(void)
{
    char fname[PATH_MAX];

    /* remove the so and user files */
    snprintf(fname, sizeof(fname), "%s/RACF", ICSF_CONFIG_PATH);
    remove_file(fname);
}

static int retrieve_all(void)
{
    size_t tokenCount;
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

    return 0;
}

static int secure_racf_passwd(const char *racfpwd, unsigned int len)
{
    const char *sopin;
    char *buf_so = NULL;
    unsigned char masterkey[AES_KEY_SIZE_256];
    char fname[PATH_MAX];
    int rc;

    /* get the SO PIN */
    sopin = pin_prompt(&buf_so, "Enter the SO PIN: ");
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
    rc = secure_racf(NULL, (CK_BYTE *)racfpwd, len, masterkey, AES_KEY_SIZE_256);
    if (rc != 0) {
        fprintf(stderr, "Failed to secure racf passwd.\n");
        rc = -1;
        goto cleanup;
    }

    /* now secure the master key with a derived key */
    /* first get the filename to put the  encrypted masterkey */
    snprintf(fname, sizeof(fname), "%s/MK_SO", ICSF_CONFIG_PATH);
    rc = secure_masterkey(NULL, masterkey, AES_KEY_SIZE_256, (CK_BYTE *)sopin,
                          strlen(sopin), fname);

    if (rc != 0) {
        fprintf(stderr, "Failed to secure masterkey.\n");
        /* remove the racf file */
        remove_racf_file();
        rc = -1;
        goto cleanup;
    }

cleanup:
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

            /* bind to ldap server */
            rc = icsf_login(&ld, uri, binddn, racfpwd);
        } else {
            rc = icsf_sasl_login(&ld, uri, NULL, NULL, NULL, NULL);
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
            rc = retrieve_all();
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
        }
        if (flags & CFG_MECH_SIMPLE) {
            /* when using simple auth, secure racf passwd. */
            rc = secure_racf_passwd(racfpwd, strlen(racfpwd));
            if (rc != 0)
                goto cleanup;
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
