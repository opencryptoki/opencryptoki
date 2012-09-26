%{
/* Parser for /etc/opencryptoki.conf */

#include <stdio.h>
#include <stdlib.h>

#include "parser.h"

int line_num = 1;

%}

%option noyywrap

%%

[\t ]+ 			/* ignore spaces */ ;

= 			return EQUAL;

\{			return BEGIN_DEF;

\n\{			{
			  line_num++;
			  return BEGIN_DEF;
			}


\}			 return END_DEF;

\n|#.*\n		{
			  line_num++;
			  return EOL;
			}

[0-9]+			{ /* number */
			  yylval.num = strtoul(yytext, NULL, 10);
			  return INTEGER;
			}

version                 return OCKVERSION;
slot                    return SLOT;

[^\"= \t\n]+		{
			  yylval.str = strdup(yytext);
			  return STRING;
			}

\"[^\"\n]*\"		{
			  yylval.str = strdup(yytext+1);
			  if (yylval.str) yylval.str[strlen(yylval.str)-1]='\0';
			  return STRING;
			}

.			yyerror(yytext);

%%
