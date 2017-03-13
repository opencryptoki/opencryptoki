/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

%{
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include "pkcs11types.h"
#include "icsf_config.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

/* Global vars used as parameter to bison/flex parser. */
extern FILE *yyin;
CK_SLOT_ID in_slot_id;
int expected_slot;
struct icsf_config out_config;
char out_str_mech[64] = "";
int out_rc;

/* Function used to report error. */
void yyerror(const char *str);

extern int yylex();

/* */
struct ref {
	char *key;
	char *addr;
	size_t len;
	int required;
};
struct ref refs[] = {
	{ "token_name",		out_config.name,	sizeof(out_config.name),	1 },
	{ "token_manufacture",	out_config.manuf,	sizeof(out_config.manuf),	1 },
	{ "token_model",	out_config.model,	sizeof(out_config.model),	1 },
	{ "token_serial",	out_config.serial,	sizeof(out_config.serial),	1 },
	{ "mech",		out_str_mech,		sizeof(out_str_mech),		1 },
	{ "uri",		out_config.uri,		sizeof(out_config.uri),		0 },
	{ "binddn",		out_config.dn,		sizeof(out_config.dn),		0 },
	{ "cacert",		out_config.ca_file,	sizeof(out_config.ca_file),	0 },
	{ "cert",		out_config.cert_file,	sizeof(out_config.cert_file),	0 },
	{ "key",		out_config.key_file,	sizeof(out_config.key_file),	0 },
};
size_t refs_len = sizeof(refs)/sizeof(*refs);
%}

%union {
	unsigned int num;
	char *str;
};

%token <str> STRING
%token <num> INTEGER
%token SLOT
%token BEGIN_DEF
%token END_DEF
%token EQUAL

%%

slots:
	slots slot
	|
	;

slot:
	SLOT INTEGER
	{
		expected_slot = ($2 == in_slot_id);
	}
	BEGIN_DEF key_values END_DEF
	;

key_values:
	key_values key_value
	|
	;

key_value:
	STRING EQUAL STRING
	{
		char *key = $1;
		char *value = $3;
		size_t i;

		/* Check if this keyword belongs to the expected slot. */
		if (!expected_slot || out_rc)
			goto done;

		/* Check key and value */
		if (!key || !value) {
			out_rc = 1;
			TRACE_ERROR("Null %s found.\n", (!key) ? "key" : "value");
			goto done;
		}

		/* Check if this keyword is expected. */
		for (i = 0; i < strlen(key); i++)
			key[i] = tolower(key[i]);

		for(i = 0; i < refs_len; i++) {
			if (!strcmp(refs[i].key, key)) {
				strncpy(refs[i].addr, value, refs[i].len);
				refs[i].addr[refs[i].len - 1] = '\0';
				goto done;
			}
		}

		out_rc = 1;
		TRACE_ERROR("Invalid keyword: %s\n", key);

	done:
		if (key)
			free(key);
		if (value)
			free(value);
	}
	;

%%

void
yyerror(const char *str)
{
	out_rc = 1;
	fprintf(stderr,"Error: %s\n", str);
	TRACE_DEBUG("Failed to parse config file. %s\n", str);
}

static int
check_keys(const char *conf_name)
{
	size_t i;

	for (i = 0; i < refs_len; i++) {
		if (refs[i].required && *refs[i].addr == '\0') {
			TRACE_ERROR("Missing required key \"%s\" in \"%s\".\n",
				      refs[i].key, conf_name);
			return -1;
		}
	}

	return 0;
}

/*
 * Parse config file using yacc.
 */
CK_RV
parse_config_file(const char *conf_name, CK_SLOT_ID slot_id,
		  struct icsf_config *data)
{
	CK_RV rc;
	struct stat stat_info;

	/* Check is file exists. */
	if (stat(conf_name, &stat_info) || !S_ISREG(stat_info.st_mode)) {
		TRACE_ERROR("File \"%s\" does not exist or is invalid.\n",
			      conf_name);
		return CKR_FUNCTION_FAILED;
	}

	/* Set parameters used by the parser */
	in_slot_id = slot_id;
	out_rc = 0;
	memset(&out_config, 0, sizeof(*data));
	expected_slot = FALSE;

	/* Open config file */
	yyin = fopen(conf_name, "r");
	if (yyin == NULL) {
		TRACE_ERROR("Failed to open \"%s\".\n", conf_name);
		return CKR_FUNCTION_FAILED;
	}

	/* Parse config file */
	rc = yyparse();
	fclose(yyin);
	if (rc || out_rc) {
		TRACE_ERROR("Failed to parser file \"%s\" (%lu:%d).\n",
			      conf_name, rc, out_rc);
		return CKR_FUNCTION_FAILED;
	}

	/* Check required keys*/
	if (check_keys(conf_name))
		return CKR_FUNCTION_FAILED;

	/* Parse mechanism type */
	if (!strcmp(out_str_mech, "SIMPLE")) {
		out_config.mech = ICSF_CFG_MECH_SIMPLE;
	} else if (!strcmp(out_str_mech, "SASL")) {
		out_config.mech = ICSF_CFG_MECH_SASL;
	} else {
		TRACE_ERROR("Unknown mechanism type found: %s\n", out_str_mech);
		return CKR_FUNCTION_FAILED;
	}

	/* Copy output data. */
	memcpy(data, &out_config, sizeof(*data));

	#if DEBUG
	{
		size_t i;
		TRACE_DEVEL("ICSF configs for slot %lu.\n", slot_id);
		for (i = 0; i < refs_len; i++) {
			TRACE_DEVEL(" %s = \"%s\"\n", refs[i].key,
				      refs[i].addr);
		}
	}
	#endif

	return CKR_OK;
}
