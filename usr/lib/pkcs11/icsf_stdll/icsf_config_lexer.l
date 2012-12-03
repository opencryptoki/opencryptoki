%{
#include <string.h>
#include "icsf_config_parse.h"
%}

%option noyywrap

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
