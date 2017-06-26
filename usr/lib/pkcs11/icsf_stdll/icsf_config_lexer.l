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
#include <string.h>
#include "icsf_config_parse.h"

extern void yyerror(const char *s);

%}

%option noyywrap
%option nounput
%option noinput

%%

[\t\n ]+ {
	/* Ignore spaces */
}

#.*\n {
	/* Comment */
}

slot {
	/* Identify a definition */
	return SLOT;
}

[0-9]+ {
	/* Number */
	yylval.num = strtoul(yytext, NULL, 10);
	return INTEGER;
}

\{ {
	/* Open definition */
	return BEGIN_DEF;
}

\} {
	/* Close definition */
	return END_DEF;
}

= {
	/* Assignment */
	return EQUAL;
}

[^\"= \t\n]+ {
	/* String */
	yylval.str = strdup(yytext);
	return STRING;
}

\"[^\"\n]*\" {
	/* Quoted string */
	yylval.str = strdup(yytext + 1);
	if (yylval.str && yylval.str[0])
		yylval.str[strlen(yylval.str) - 1] = '\0';
	return STRING;
}

. {
	/* Default */
	yyerror(yytext);
}

%%
