/*
 * Licensed materials, Property of IBM Corp.
 *
 * OpenCryptoki ICSF token configuration tool.
 *
 * (C) COPYRIGHT International Business Machines Corp. 2012
 *
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "icsf.h"
#include "slotmgr.h"
#include "pbkdf.h"
#include "defs.h"

#define CFG_ADD		0x0001
#define CFG_LIST	0x0002
#define CFG_BINDDN	0x0004
#define CFG_CERT        0x0008
#define CFG_PRIVKEY     0x0010
#define CFG_CACERT      0x0020
#define CFG_URI		0x0040
#define CFG_MECH	0x0080
#define CFG_MECH_SASL	0x0100
#define CFG_MECH_SIMPLE	0x0200

#define MAX_RECORDS	10
#define SALT_SIZE	16
#define SASL	"sasl"
#define SLOT	"slot"

#define TMPSIZ 64
#define LINESIZ 512
#define TOKBUF	2056
#define STDLL	"libpkcs11_icsf.so"

LDAP *ld;
char *binddn = NULL;
char *uri = NULL;
char *mech = NULL;
char *cert = NULL;
char *cacert = NULL;
char *privkey = NULL;
unsigned long flags = 0;

void
usage(char *progname)
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

int
get_pin(char **pin, size_t *pinlen)
{
	struct termios old, new;
	int nread;
	char *buff = NULL;
	size_t buflen;
	int rc = 0;

	/* turn echoing off */
	if (tcgetattr(fileno(stdin), &old) != 0)
		return -1;

	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr (fileno(stdin), TCSAFLUSH, &new) != 0)
		return -1;

	/* read the pin
	 * Note: getline will allocate memory for buff. free it when done.
	 */
	nread = getline(&buff, &buflen, stdin);
	if (nread == -1) {
		rc = -1;
		goto done;
	}

	/* Restore terminal */
	(void) tcsetattr(fileno(stdin), TCSAFLUSH, &old);

	/* start a newline */
	printf("\n");
	fflush(stdout);

	/* Allocate  PIN.
	* Note: nread includes carriage return.
	* Replace with terminating NULL.
	*/
	*pin = (unsigned char *)malloc(nread);
        if (*pin == NULL) {
                rc = -ENOMEM;
		goto done;
	}

	/* strip the carriage return since not part of pin. */
	buff[nread - 1] = '\0';
	memcpy(*pin, buff, nread);
	/* don't include the terminating null in the pinlen */
	*pinlen = nread - 1;

done:
	if (buff)
		free(buff);

	return rc;
}

int
get_start_slot(void)
{

	FILE *fp;
	char temp[LINESIZ];
	int num;
	int found = -1;
	struct stat statbuf;

	/* if file doesn't exist, then first slot will be 0. */
	if ((stat(OCK_CONFIG, &statbuf) < 0) && (errno == ENOENT))
		return 0;

	fp = fopen(OCK_CONFIG, "r");
	if (fp == NULL) {
		fprintf(stderr, "open failed, line %d: %s\n",
			__LINE__, strerror(errno));
                return(-1);
	}

	/* step thru config file and get biggest slot number used */
	while (fgets(temp, LINESIZ, fp) != NULL) {
		if (strstr(temp, SLOT) != NULL) {
			if (sscanf(temp, "%*s %d", &num) == 1)
				if (num > found)
					found = num;
		}
	}

	/* bump up the slot number, since this will be next new slot entry.
	 * if it was an empty file or a file with no slot entries,
	 * then next new slot entry will be 0.
	 */

	fclose(fp);
	return (++found);
}

int
remove_file(char *filename)
{
	struct stat statbuf;

	/* if file exists, then remove it */
	if ((stat(filename, &statbuf) < 0) && (errno == ENOENT)) {
		if (unlink(filename) == -1) {
			fprintf(stderr, "unlink failed for %s, line %d: %s\n",
				filename, __LINE__, strerror(errno));
				return(-1);
		}
	}
	return 0;
}

static void
add_token_config_entry(FILE *fp, const char *key, const char *value)
{
	if (!key || !value)
		return;
	fprintf(fp, "%s = \"%s\"\n", key, value);
}

int
add_token_config(const char *configname, struct icsf_token_record token, int slot)
{
	FILE *tfp;
	int rc = 0;

	/* create the token config file */
	tfp = fopen(configname, "w");
	if (tfp == NULL) {
		fprintf(stderr, "fopen failed, line %d: %s\n",
			__LINE__, strerror(errno));
		return (-1);
	}

	/* add the info */
	fprintf(tfp, "slot %d {\n", slot);
	add_token_config_entry(tfp, "TOKEN_NAME", token.name);
	add_token_config_entry(tfp, "TOKEN_MANUFACTURE", token.manufacturer);
	add_token_config_entry(tfp, "TOKEN_MODEL", token.model);
	add_token_config_entry(tfp, "TOKEN_SERIAL", token.serial);
	add_token_config_entry(tfp, "MECH", (flags & CFG_MECH_SIMPLE)
			? "SIMPLE" : "SASL" );

	/* add BIND info */
	if (memcmp(mech, "simple", strlen("simple")) == 0) {
		add_token_config_entry(tfp, "BINDDN", binddn);
		add_token_config_entry(tfp, "URI", uri);
	} else {
		add_token_config_entry(tfp, "URI", uri);
		add_token_config_entry(tfp, "CERT", cert);
		add_token_config_entry(tfp, "CACERT", cacert);
		add_token_config_entry(tfp, "KEY", privkey);
	}

	fprintf(tfp, "}\n");

	fflush(tfp);
	if (ferror(tfp) != 0) {
                fprintf(stderr, "failed to add token named, %s\n", token.name);
		rc = -1;
	}

	fclose(tfp);
	return(rc);
}

int
config_add_slotinfo(int num_of_slots, struct icsf_token_record *tokens)
{
	struct stat statbuf;
	FILE *fp;
	int start_slot = -1;
	char configname[LINESIZ];
	int i, rc;

	/* get the starting slot for next entry */
	start_slot = get_start_slot();
	if (start_slot == -1)
		return (-1);

	/* open the config file. if it doesn't exist, create it */
	if ((stat(OCK_CONFIG, &statbuf) == -1) && (errno == ENOENT))
		/* doesn't exist, create it */
		fp = fopen(OCK_CONFIG, "w");
	else
		fp = fopen(OCK_CONFIG, "a");

	if (fp == NULL) {
		fprintf(stderr, "open failed, line %d: %s\n",
			__LINE__, strerror(errno));
		return (-1);
	}

	/* For each token in the list do,
	 *      - Create a slot entry in ock config file that contains
	 *        the stdll and token config name.
	 *      - Create a token config file that contains the token info
	 *        from the ICSF and the BIND authentication info.
	 */
	for (i = 0; i < num_of_slots; i++) {

		/* create the config name using the token's name */
		memset(configname, 0, sizeof(configname));
		snprintf(configname, sizeof(configname), "%s/%s.conf",
			 OCK_CONFDIR, tokens[i].name);

		/* write the token info to the token's config file */
		rc = add_token_config(configname, tokens[i], start_slot);
		if (rc == -1) {
			fprintf(stderr, "failed to add %s token.\n",
				tokens[i].name);
			/* skip adding this entry */
			continue;
		}

		/* add the slot entry to the ock config file */
		fprintf(fp, "\nslot %d {\n", start_slot);
		fprintf(fp, "stdll = %s\n", STDLL);
		fprintf(fp, "confname = %s\n", configname);
		fprintf(fp, "}\n");
		fflush(fp);
		if (ferror(fp) != 0) {
			fprintf(stderr, "Failed to add an entry for %s token: "
				"%s\n", tokens[i].name, strerror(errno));
			remove_file(configname);
			continue;
		}

		/* bump the slot number */
		start_slot++;
	}

	fclose(fp);
	return (0);
}

int
list_tokens(void)
{
	size_t tokenCount = MAX_RECORDS;
	struct icsf_token_record *previous = NULL;
	struct icsf_token_record tokens[MAX_RECORDS];
	int rc, i, num_seen = 0;

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
				tokens[i].flags ? "yes" : "no");
			num_seen++;
		}

		if (tokenCount)
			previous = &tokens[tokenCount - 1];

	} while (tokenCount);

	return 0;
}

int
lookup_name(char *name, struct icsf_token_record *found)
{
	size_t tokenCount = MAX_RECORDS;
	struct icsf_token_record *previous = NULL;
	struct icsf_token_record tokens[MAX_RECORDS];
	int rc, i;

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
				memcpy(found, &tokens[i],
					sizeof(struct icsf_token_record));
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

void
remove_racf_file(void)
{
	unsigned char fname[PATH_MAX];

	/* remove the so and user files */
	snprintf(fname, sizeof(fname), "%s/RACF", ICSF_CONFIG_PATH);
	remove_file(fname);
}

int
retrieve_all(void)
{
	size_t tokenCount;
	struct icsf_token_record *previous = NULL;
	struct icsf_token_record tokens[MAX_RECORDS];
	int rc;


	/* since pkcsslotd can only manage
	 * NUMBER_SLOTS_MANAGED at a time, use this as
	 * the maxiumum amount of tokens to retrieve...
	 */
	tokenCount = NUMBER_SLOTS_MANAGED;
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

int
secure_racf_passwd(char *racfpwd, unsigned int len)
{
	char *sopin = NULL;
	char masterkey[AES_KEY_SIZE_256];
	char fname[PATH_MAX];
	int rc;
	size_t sopinlen;


	/* get the SO PIN */
	printf("Enter the SO PIN: ");
	fflush(stdout);
	rc = get_pin(&sopin, &sopinlen);
	if (rc != 0) {
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
	rc = secure_racf(racfpwd, len, masterkey, AES_KEY_SIZE_256);
	if (rc != 0) {
		fprintf(stderr, "Failed to secure racf passwd.\n");
		rc = -1;
		goto cleanup;
	}

	/* now secure the master key with a derived key */
	/* first get the filename to put the  encrypted masterkey */
	snprintf(fname, sizeof(fname), "%s/MK_SO", ICSF_CONFIG_PATH);
	rc = secure_masterkey(masterkey, AES_KEY_SIZE_256, sopin,
				strlen(sopin), fname);

	if (rc != 0) {
		fprintf(stderr, "Failed to secure masterkey.\n");
		/* remove the racf file */
		remove_racf_file();
		rc = -1;
		goto cleanup;
	}

cleanup:
	if (sopin)
		free(sopin);

	return rc;
}

int
main(int argc, char **argv)
{
	char *racfpwd = NULL;
	size_t racflen;
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
				fprintf(stderr, "strdup failed: line %d\n",
					__LINE__);
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
				fprintf(stderr, "strdup failed: line %d\n",
					__LINE__);
				goto cleanup;
			}
			break;
		case 'c':
			flags |= CFG_CERT;
			if ((cert = strdup(optarg)) == NULL) {
				rc = -1;
				fprintf(stderr, "strdup failed: line %d\n",
					__LINE__);
				goto cleanup;
			}
			break;
		case 'k':
			flags |= CFG_PRIVKEY;
			if ((privkey = strdup(optarg)) == NULL) {
				rc = -1;
				fprintf(stderr, "strdup failed: line %d\n",
					__LINE__);
				goto cleanup;
			}
			break;
		case 'C':
			flags |= CFG_CACERT;
			if ((cacert = strdup(optarg)) == NULL) {
				rc = -1;
				fprintf(stderr, "strdup failed: line %d\n",
					__LINE__);
				goto cleanup;
			}
			break;
		case 'u':
			flags |= CFG_URI;
			if ((uri = strdup(optarg)) == NULL) {
				rc = -1;
				fprintf(stderr, "strdup failed: line %d\n",
					__LINE__);
				goto cleanup;
			}
			break;
		case 'm':
			flags |= CFG_MECH;
			if ((mech = strdup(optarg)) == NULL) {
				rc = -1;
				fprintf(stderr, "strdup failed: line %d\n",
					__LINE__);
				goto cleanup;
			}
			if (memcmp(mech, SASL, sizeof(SASL)) == 0)
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
	if ((!flags) || (!(flags & CFG_ADD) && !(flags & CFG_LIST )))
		usage(argv[0]);

	/* Currently, do not allow user to add a list of tokens.
	 * When ready to support multiple icsf tokens, this
	 * check can be removed.
	 */
	if ((flags & CFG_ADD) && !(memcmp(tokenname, "all", strlen(tokenname))))
		usage(argv[0]);

	/* If add, then must specify a mechanism and a name*/
	if ((flags & CFG_ADD ) && (!(flags & CFG_MECH) || tokenname == NULL))
		usage(argv[0]);

	/* If list, then must specify a mechanism */
	if ((flags & CFG_LIST ) && !(flags & CFG_MECH))
		usage(argv[0]);

	/* Cannot add and list at the same time */
	if ((flags & CFG_LIST ) && (flags & CFG_ADD))
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

	/* get racf password if needed */
	if ((flags & CFG_ADD) || (flags & CFG_LIST)) {
		if (flags & CFG_MECH_SIMPLE) {
			printf("Enter the RACF passwd: ");
			fflush(stdout);
			rc = get_pin(&racfpwd, &racflen);
			if (rc != 0) {
				fprintf(stderr, "Could not get RACF passwd.\n");
				return (-1);
			}

			/* bind to ldap server */
			rc = icsf_login(&ld, uri, binddn, racfpwd);
		} else {
			rc = icsf_sasl_login(&ld, uri, NULL, NULL, NULL, NULL);
		}
		if (rc) {
			fprintf(stderr, "Failed to bind to the ldap server.\n");
			goto cleanup;
		}
	}


	/* Add token(s) */
	if (flags & CFG_ADD) {
		if (memcmp(tokenname, "all", strlen(tokenname)) == 0) {
			rc = retrieve_all();
			if (rc) {
				fprintf(stderr, "Could not add the list of "
						"tokens.\n");
				goto cleanup;
			}
		} else {
			/* add only the specified tokenname.
			 * first, find it in the list.
			 */
			rc = lookup_name(tokenname, &found_token);
			if (rc != 0) {
				fprintf(stderr,
					"Could not find %s in token list.\n",
					tokenname);
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
	if (racfpwd)
		free(racfpwd);
	return rc;
}
