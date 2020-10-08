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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "slotmgr.h"
#include "configparser.h"

static struct strholder {
    struct strholder *prev;
    char *str;
} *strroot;

struct parsefuncs *parsefuncs;
void *parsedata;

extern FILE *yyin;
extern int yyparse();
extern void yyerror(const char *s);
extern int line_num;
extern int yylex();

static void configparse_freestrings(void);
static void configparse_freestringsfrom(char *str);

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

int lookup_keyword(const char *key);

%}

%union {
	char *str;
	unsigned int num;
    int err;
}

%token EQUAL DOT SLOT EOL OCKVERSION BEGIN_DEF END_DEF
%token <str> STRING
%token <str> KEYWORD
%token <num> INTEGER
%token <num> TOKVERSION
%token <str> COMMENT

%%

config_file:
	config_file sections
	|
	;

sections:
	version_def eolcomments
	| SLOT INTEGER BEGIN_DEF
	{
        if (parsefuncs->begin_slot && parsefuncs->begin_slot(parsedata, $2, 0)) {
            if (parsefuncs->parseerror)
                parsefuncs->parseerror(parsedata, line_num, NULL);
            YYERROR;
        }
	} eolcomments keyword_defs END_DEF
	{
        if (parsefuncs->end_slot && parsefuncs->end_slot(parsedata)) {
            if (parsefuncs->parseerror)
                parsefuncs->parseerror(parsedata, line_num, NULL);
            YYERROR;
        }
	}
	| SLOT INTEGER EOL BEGIN_DEF
	{
        if (parsefuncs->begin_slot && parsefuncs->begin_slot(parsedata, $2, 1)) {
            if (parsefuncs->parseerror)
                parsefuncs->parseerror(parsedata, line_num, NULL);
            YYERROR;
        }
    } eolcomments keyword_defs END_DEF
	{
        if (parsefuncs->end_slot && parsefuncs->end_slot(parsedata)) {
            if (parsefuncs->parseerror)
                parsefuncs->parseerror(parsedata, line_num, NULL);
            YYERROR;
        }
	}
	| eolcomments
	;

version_def:
    OCKVERSION STRING
    {
        if (parsefuncs->version && parsefuncs->version(parsedata, $2)) {
            if (parsefuncs->parseerror)
                parsefuncs->parseerror(parsedata, line_num, NULL);
            configparse_freestringsfrom($2);
            YYERROR;
        }
        configparse_freestringsfrom($2);
    }

line_def:
    STRING EQUAL TOKVERSION
    {
        int kw;
        char errbuf[256];

        kw = lookup_keyword($1);
        if (kw == -1) {
            if (parsefuncs->parseerror) {
                snprintf(errbuf, sizeof(errbuf), "Unknown keyword: \"%s\"", $1);
                parsefuncs->parseerror(parsedata, line_num, errbuf);
            }
            configparse_freestringsfrom($1);
            YYERROR;
        }
        configparse_freestringsfrom($1);
        if (parsefuncs->key_vers) {
            if(parsefuncs->key_vers(parsedata, kw, $3)) {
                if (parsefuncs->parseerror)
                    parsefuncs->parseerror(parsedata, line_num, NULL);
                YYERROR;
            }
        }
    }
    |
    STRING EQUAL STRING
    {
        int kw;
        char errbuf[256];

        kw = lookup_keyword($1);
        if (kw == -1) {
            if (parsefuncs->parseerror) {
                snprintf(errbuf, sizeof(errbuf), "Unknown keyword: \"%s\"", $1);
                parsefuncs->parseerror(parsedata, line_num, errbuf);
            }
            configparse_freestringsfrom($3);
            YYERROR;
        }
        if (parsefuncs->key_str && parsefuncs->key_str(parsedata, kw, $3)) {
            if (parsefuncs->parseerror)
                parsefuncs->parseerror(parsedata, line_num, NULL);
            configparse_freestringsfrom($3);
            YYERROR;
        }
        configparse_freestringsfrom($3); // Will also free $1
    }

keyword_defs:
    line_def eolcomments keyword_defs
    |
    eolcomments keyword_defs
    |
    /* empty */

eolcomments:
    eolcomment eolcomments
    |
    eolcomment

eolcomment:
    COMMENT EOL
    {
        if (parsefuncs->eolcomment)
            parsefuncs->eolcomment(parsedata, $1);
        if (parsefuncs->eol)
            parsefuncs->eol(parsedata);
        configparse_freestringsfrom($1);
    }
    |
    EOL
    {
        if (parsefuncs->eol)
            parsefuncs->eol(parsedata);
    }

%%

char *configparse_strdup(char *val)
{
    struct strholder *holder;
    char *res = NULL;

    holder = (struct strholder *)malloc(sizeof(struct strholder));
    if (holder) {
        holder->prev = strroot;
        strroot = holder;
        holder->str = res = strdup(val);
    }
    return res;
}

static void configparse_freestrings()
{
    struct strholder *cur, *next;

    cur = strroot;
    while (cur) {
        next = cur->prev;
        free(cur->str);
        free(cur);
        cur = next;
    }
    strroot = NULL;
}

static void configparse_freestringsfrom(char *str)
{
    struct strholder *cur, *next, **anchor;

    anchor = &strroot;
    cur = strroot;
    while (cur && cur->str != str) {
        anchor = &cur->prev;
        cur = cur->prev;
    }
    while (cur) {
        next = cur->prev;
        free(cur->str);
        free(cur);
        cur = next;
    }
    *anchor = NULL;
}

void
yyerror(const char *s)
{
    if (parsefuncs->parseerror)
        parsefuncs->parseerror(parsedata, line_num, s);
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

const char *keyword_token_to_str(int tok)
{
	return tok < KW_MAX ? ock_keywords[tok].name : "<UNKNWON>";
}

int
load_and_parse(const char *configfile, struct parsefuncs *funcs, void *private)
{

	FILE *conf;
	int res;

	extern FILE *yyin;

	conf = fopen(configfile, "r");

	if (!conf) {
		fprintf(stderr, "Failed to open %s: %s\n", configfile, strerror(errno));
		return -1;
	}

    line_num = 1;
	yyin = conf;
	parsefuncs = funcs;
	parsedata = private;
    strroot = NULL;
    
	res = yyparse();

	fclose(conf);
	parsefuncs = NULL;
	parsedata = NULL;
    configparse_freestrings();

	return res;
}
