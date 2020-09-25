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
/*
 * Parse openCryptoki's config file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "slotmgr.h"
#include "configparser.h"

Slot_Info_t_64 sinfo_struct;
unsigned long int Index;
struct config_parse_env *env;

#define ERRSTRLEN	256
#define DEF_MANUFID	"IBM"
#define DEF_SLOTDESC	"Linux"

static char errbuf[ERRSTRLEN + 1];

extern char *strsep(char **stringp, const char *delim);
extern FILE *yyin;
extern int yyparse();
extern void yyerror(const char *s);
extern int line_num;
extern int yylex();

typedef enum {
	KW_STDLL,
	KW_SLOTDESC,
	KW_MANUFID,
	KW_HWVERSION,
	KW_FWVERSION,
	KW_CONFNAME,
	KW_TOKNAME,
	KW_TOKVERSION,
	KW_MAX
} keyword_token;

struct ock_key {
	char *name;
	keyword_token token;
};

static const struct ock_key ock_keywords[] = {
	{"stdll",       	KW_STDLL},
	{"description", 	KW_SLOTDESC},
	{"manufacturer",	KW_MANUFID},
	{"hwversion",		KW_HWVERSION},
	{"firmwareversion",	KW_FWVERSION},
	{"confname",		KW_CONFNAME},
	{"tokname",		KW_TOKNAME},
	{"tokversion",		KW_TOKVERSION}
};

void set_init(void);
void set_defaults(void);
int lookup_keyword(const char *key);
int do_str(char *slotinfo, size_t size, char* kw, char *val);
int do_vers(CK_VERSION *slotinfo, char *kw, char *val);

%}

%union {
	char *str;
	unsigned int num;
    int err;
}

%type <err> keyword_defs
%token EQUAL DOT SLOT EOL OCKVERSION BEGIN_DEF END_DEF
%token <str> STRING
%token <str> KEYWORD
%token <num> INTEGER
%token <num> TOKVERSION

%%

config_file:
	config_file sections
	|
	;

sections:
	OCKVERSION STRING EOL
	{
		free($2);
	}
	| SLOT INTEGER BEGIN_DEF EOL
	{
		/* inititalize sinfo_struct */
		set_init();
		sinfo_struct.slot_number = $2;
		Index = $2;

	} keyword_defs[errcnt] END_DEF
	{
		/* set some defaults if needed before copying */
		set_defaults();
        if (Index >= NUMBER_SLOTS_MANAGED) {
            yyerror("Slot number too big.  Skipping slot.");
            /* Should we YYABORT here? */
        } else if ($errcnt == 0) {
            memcpy(&env->sinfo[Index], &sinfo_struct, sizeof(sinfo_struct));
            env->NumberSlotsInDB++;
        }
	}
	| EOL
	;

keyword_defs:
	STRING EQUAL TOKVERSION EOL keyword_defs
	{
		int kw;

		kw = lookup_keyword($1);

		switch (kw) {
		case KW_TOKVERSION:
			sinfo_struct.version = $3;
			break;
		default:
			yyerror("unknown config keyword");
			break;
		}
        $$ = $5;
	}
	| STRING EQUAL STRING EOL keyword_defs
	{
		int kw;
        int err = 0;

		kw = lookup_keyword($1);

		switch (kw) {
		case KW_STDLL:
            memset(sinfo_struct.dll_location, 0, sizeof(sinfo_struct.dll_location));
            if (strlen($3) >= sizeof(sinfo_struct.dll_location)) {
                yyerror("STDLL location too long.  Skipping token.");
                err = -1;
            } else {
                sinfo_struct.present = TRUE;
                sinfo_struct.pk_slot.flags |= (CKF_TOKEN_PRESENT);
                memcpy(sinfo_struct.dll_location, $3, strlen($3));
            }
			break;
		case KW_SLOTDESC:
			err = do_str((char *)sinfo_struct.pk_slot.slotDescription,
			  sizeof(sinfo_struct.pk_slot.slotDescription), $1, $3);
			break;
		case KW_MANUFID:
			err = do_str((char *)sinfo_struct.pk_slot.manufacturerID,
			   sizeof(sinfo_struct.pk_slot.manufacturerID), $1, $3);
			break;
		case KW_HWVERSION:
			err = do_vers(&sinfo_struct.pk_slot.hardwareVersion, $1, $3);
			break;
		case KW_FWVERSION:
			err = do_vers(&sinfo_struct.pk_slot.firmwareVersion, $1, $3);
			break;
		case KW_CONFNAME:
            if (strlen($3) >= sizeof(sinfo_struct.confname)) {
                yyerror("STDLL configuration name too long.  Skipping token.");
                err = -1;
            } else {
                memset(sinfo_struct.confname, 0, sizeof(sinfo_struct.confname));
                memcpy(sinfo_struct.confname, $3, strlen($3));
            }
			break;
		case KW_TOKNAME:
            if (strlen($3) >= sizeof(sinfo_struct.tokname)) {
                yyerror("Token name too long.  Skipping token.");
                err = -1;
            } else {
                memset(sinfo_struct.tokname, 0, sizeof(sinfo_struct.tokname));
                memcpy(sinfo_struct.tokname, $3, strlen($3));
            }
			break;
		default:
			yyerror("unknown config keyword");
            /* TODO: Set err? */
			break;
		}
		free ($3);
        $$ = err + $5;
	}
	|
	{ $$ = 0; };

%%

void
yyerror(const char *s)
{
	fprintf(stderr, "parse error on line %d: %s\n", line_num, s);
}

void
set_init(void)
{
	memset(&sinfo_struct, 0, sizeof(sinfo_struct));
}

void
set_defaults(void)
{
	/* set some defaults if user hasn't set these. */
	if (!sinfo_struct.pk_slot.slotDescription[0]) {
		memset(&sinfo_struct.pk_slot.slotDescription[0], ' ',
		       sizeof(sinfo_struct.pk_slot.slotDescription));
		memcpy(&sinfo_struct.pk_slot.slotDescription[0],
			DEF_SLOTDESC, strlen(DEF_SLOTDESC));
	}
	if (!sinfo_struct.pk_slot.manufacturerID[0]) {
		memset(&sinfo_struct.pk_slot.manufacturerID[0], ' ',
		       sizeof(sinfo_struct.pk_slot.manufacturerID));
		memcpy(&sinfo_struct.pk_slot.manufacturerID[0],
			DEF_MANUFID, strlen(DEF_MANUFID));
	}
}

int
do_str(char *slotinfo, size_t size, char* kw, char *val)
{
	if (strlen(val) > size) {
		snprintf(errbuf, ERRSTRLEN, "%s has too many characters\n", kw);
		yyerror(errbuf);
		return -1;
	}
	memcpy(slotinfo, val, strlen(val));
	return 0;
}

int
do_vers(CK_VERSION *slotinfo, char *kw, char *val)
{
	char **ap, *argp[2];
	char *valp;

	if (!val) {
		snprintf(errbuf, ERRSTRLEN, "%s has no value\n", kw);
		yyerror(errbuf);
		return -1 ;
	}

	valp = val;
	for (ap = argp; (*ap = strsep(&valp, ".")) != NULL;)
		if (**ap != '\0')
			if (++ap >= &argp[2])
				break;

	slotinfo->major = (char) atoi(argp[0]);
	if(!argp[1])
		slotinfo->minor = 0;
	else
		slotinfo->minor = (char) atoi(argp[1]);

	return 0;
}

int
lookup_keyword(const char *key)
{
	int i;

	for (i = 0; i < KW_MAX ; i++ ) {
		if (strncmp(key, ock_keywords[i].name, strlen(key)) == 0)
			return ock_keywords[i].token;
	}
	/* if we get here that means did not find a match... */
	return -1;
}

int
load_and_parse(const char *configfile, struct config_parse_env *envp)
{

	FILE *conf;

	extern FILE *yyin;

	conf = fopen(configfile, "r");

	if (!conf) {
		fprintf(stderr, "Failed to open %s: %s\n", configfile, strerror(errno));
		return -1;
	}

	yyin = conf;
    env = envp;
    env->NumberSlotsInDB = 0;
    
	do {
		yyparse();

	} while (!feof(yyin));

	fclose(conf);

	return 0;
}
