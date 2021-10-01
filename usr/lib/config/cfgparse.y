/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

%{
/*
 * Generic config file parser.
 */
#include <errno.h>
%}

%code requires {
#include "configuration.h"
typedef void* configscan_t;

typedef void (*error_hook_f)(int line, int col, const char *msg);
}

%code provides
{
  // Tell Flex the expected prototype of yylex.
  #define YY_DECL                             \
    int configlex (CONFIGSTYPE *yylval_param, CONFIGLTYPE *yylloc_param, configscan_t yyscanner)

  // Declare the scanner.
  YY_DECL;

 
  static inline void configerror(CONFIGLTYPE *lloc, configscan_t scanner,
                                 struct ConfigBaseNode **res,
                                 error_hook_f error_hook,
                                 int trackComments,
                                 const char *msg)
  {
    (void)scanner;
    (void)res;
    (void)trackComments;
    if (error_hook) {
      error_hook(lloc->first_line, lloc->first_column, msg);
    }
  }
}

%union {
  char *str;
  unsigned long num;
  struct ConfigBaseNode *node;
}

%token
        EOL
        EQUAL
        BEGIN_DEF
        END_DEF
        BEGIN_LIST
        END_LIST
        COMMA
        FILEVERSION
  <num> NUMBER
  <num> VERSION_TOK
  <str> BARE
  <str> COMMENT_TOK
  <str> STRING_TOK

%type <node>       configelemstar configelem barelist barelist_ne
                   eoc eocstar eocplus commentedconfigelemstar

%defines
%destructor { free($$); } <str>
%destructor { confignode_deepfree($$); } <node>
%define api.pure full
%locations
%define api.prefix {config}
%lex-param   { configscan_t scanner }
%parse-param   { configscan_t scanner }
%parse-param   { struct ConfigBaseNode **res }
%parse-param   { error_hook_f error_hook }
%parse-param   { int trackComments }
%define parse.trace
%define parse.error verbose
%define parse.lac full
%%

/* Parse the whole config file:
configfile ::= commentedconfigelem*
*/
configfile:
    commentedconfigelemstar { *res = $1; $1 = NULL; }

/* Parse configelemstar that might start with an arbitrary number of
   initial comments.  This is used to take care of comments before the
   first configelem.  The rules for configelem take care of comments
   after the configelem.  Since "after configelem i" is "before
   configelem (i+1)", we cannot add comment tracking to before and
   after a configelem.  So we use this rule to fill the vacant
   position before the first configelem.
*/
commentedconfigelemstar :
    eocstar configelemstar { $$ = confignode_append($1, $2); $1 = $2 = NULL; }

/* 0-n configuration elements with comments between them. */
configelemstar:
	configelem configelemstar { $$ = confignode_append($1, $2); $1 = $2 = NULL; }
	|
	/* empty */ { $$ = NULL; }

/* Valid configuration elements:
- "version" BARE
- BARE = NUMBER
- BARE = VERSION
- BARE = STRING
- BARE = BARE
- BARE NUMBER { configelemstar }
- BARE { configelemstar }
- BARE ( barelist )

Special care has to be taken for newlines and comments.  They are
supported before and after {, }, (, and ), but not before or after =
or the special keyword "version".

Note: the lexer only emits the FILEVERSION token as first "active"
configuration element.  You may have an arbitrary number of comments and
newlines before, but the first keyword can either be version (in which case it
is seen as FILEVERSION and not BARE), or any other BARE to start a different
alternative.

Every config elem has to end with eocstar to allow an arbitrary number
of comments at the end of the element.  The element also has to take
care of all the positions where it wants to allow comments.
*/
configelem:
	/* version somestring*/
    FILEVERSION BARE eocstar {
	    struct ConfigFileVersionNode *n = confignode_allocfileversion($2, @1.first_line);
	    if (!n) { YYERROR; }
	    $$ = confignode_append(&(n->base), $3);
	    $2 = NULL;
        $3 = NULL;
        }
    |
	/* conf = 42 */
	BARE EQUAL NUMBER eocstar {
	    struct ConfigIntValNode *n = confignode_allocintval($1, $3, @1.first_line);
	    if (!n) { YYERROR; }
	    $$ = confignode_append(&(n->base), $4);
	    $1 = NULL;
        $4 = NULL;
	}
	|
	/* conf = 1.0 */
	BARE EQUAL VERSION_TOK eocstar {
	    struct ConfigVersionValNode *n = confignode_allocversionval($1, $3, @1.first_line);
	    if (!n) { YYERROR; }
	    $$ = confignode_append(&(n->base), $4);
	    $1 = NULL;
        $4 = NULL;
	}
	|
	/* conf = "A string" */
	BARE EQUAL STRING_TOK eocstar {
	    struct ConfigStringValNode *n = confignode_allocstringval($1, $3, @1.first_line);
	    if (!n) { YYERROR; }
	    $$ = confignode_append(&(n->base), $4);
	    $1 = NULL;
	    $3 = NULL;
        $4 = NULL;
	}
	|
	/* conf = configuration */
	BARE EQUAL BARE eocstar {
	    struct ConfigBareValNode *n = confignode_allocbareval($1, $3, @1.first_line);
	    if (!n) { YYERROR; }
	    $$ = confignode_append(&(n->base), $4);
	    $1 = NULL;
	    $3 = NULL;
        $4 = NULL;
	}
	|
	/* conf 42 { subconf = 73 } */
	BARE NUMBER eocstar BEGIN_DEF commentedconfigelemstar END_DEF eocstar {
	     struct ConfigIdxStructNode *n = confignode_allocidxstruct($1, $2, $3, $5, @1.first_line);
         if (!n) { YYERROR; }
	     $$ = confignode_append(&(n->base), $7);
	     $1 = NULL;
	     $3 = $5 = $7 = NULL;
	}
	|
	/* conf { subconf = 73 } */
	BARE eocstar BEGIN_DEF commentedconfigelemstar END_DEF eocstar {
        
	     struct ConfigStructNode *n = confignode_allocstruct($1, $2, $4, @1.first_line);
         if (!n) { YYERROR; }
	     $$ = confignode_append(&(n->base), $6);
	     $1 = NULL;
	     $2 = $4 = $6 = NULL;
	}
	|
	/* conf ( A, B, C ) */
	BARE eocstar BEGIN_LIST barelist END_LIST eocstar {
	     struct ConfigBareListNode *n = confignode_allocbarelist($1, $2, $4, @1.first_line);
         if (!n) { YYERROR; }
	     $$ = confignode_append(&(n->base), $6);
	     $1 = NULL;
	     $2 = $4 = $6 = NULL;
	}
    |
    BARE eocstar {
        struct ConfigBareConstNode *n = confignode_allocbareconst($1, @1.first_line);
        if (!n) { YYERROR; }
        $$ = confignode_append(&(n->base), $2);
        $1 = NULL;
        $2 = NULL;
    }

/*
A possibly empty list of barewords or comments.  Two bare words have to be
separated by a comma (see barelist_ne).
*/
barelist:
	eocstar { $$ = $1; $1 = NULL; }
	|
	eocstar barelist_ne eocstar {
		$$ = confignode_append($1, confignode_append($2, $3));
		$1 = $2 = $3 = NULL;
	}

/* Nonempty list of bare words.  If the list contains multiple elements, they
are separated by a comma.  After a comma you can optionally add as many
end-of-line comments as you wish (see eocstar).  Note that the list may not end
with a comma!
*/
barelist_ne:
	BARE COMMA eocstar barelist_ne {
	    struct ConfigBareNode *n = confignode_allocbare($1, @1.first_line);
	    if (!n) { YYERROR; }
	    $1 = NULL;
	    $$ = confignode_append(&n->base, confignode_append($3, $4));
	    $3 = $4 = NULL;
	}
	|
	BARE {
	    struct ConfigBareNode *n = confignode_allocbare($1, @1.first_line);
	    if (!n) { YYERROR; }
	    $1 = NULL;
	    $$ = &n->base;
	}

/* Either end of line comment or just end of line token.  Either way, a line
ends with this non-terminal.
*/
eoc:
	COMMENT_TOK EOL {
	    if (trackComments) {
	        struct ConfigEOCNode *eocn = confignode_alloceoc($1, @1.first_line);
	        if (!eocn) { YYERROR; };
		$1 = NULL;
		$$ = &eocn->base;
            } else {
	        $$ = NULL;
	    }
	}
	|
	EOL {
	    if (trackComments) {
	        struct ConfigEOCNode *eocn = confignode_alloceoc(NULL, @1.first_line);
	        if (!eocn) { YYERROR; };
		$$ = &eocn->base;
            } else {
	        $$ = NULL;
	    }
	}

/* BNF form of eoc* */
eocstar:
	eocplus { $$ = $1; $1 = NULL; }
	|
	/* empty */ { $$ = NULL; }

/* BNF form of eoc+ */
eocplus:
	eoc { $$ = $1; $1 = NULL; }
	|
	eoc eocplus { $$ = confignode_append($1, $2); $1 = $2 = NULL; }

%%

#include "cfglex.h"

int parse_configlib_file(FILE *conf, struct ConfigBaseNode **res,
                         error_hook_f error_hook, int trackComments)
{
	configscan_t scanner;
	int ret;

	configlex_init_extra(trackComments, &scanner);
	configset_in(conf, scanner);
	ret = configparse(scanner, res, error_hook, trackComments) ? -1 : 0;

	configlex_destroy(scanner);
	return ret;
}
