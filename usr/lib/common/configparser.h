/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _CONFIGPARSER_H
#define _CONFIGPARSER_H  1

#include <slotmgr.h>

#define DEF_MANUFID	"IBM"
#define DEF_SLOTDESC	"Linux"

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

typedef int  (*ockversion_f)(void *private, const char *version);
typedef void (*eol_f)(void *private);
typedef int  (*begin_slot_f)(void *private, int slot, int nl_before_begin);
typedef int  (*end_slot_f)(void *private);
typedef int  (*key_str_f)(void *private, int tok, const char *val);
typedef int  (*key_vers_f)(void *private, int tok, unsigned int vers);
typedef void (*eolcomment_f)(void *private, const char *comment);
/*
 * Report an error.  If the error is not reported by the parser itself
 * but via one of the parse functions, \c parsermsg will be \c NULL.
 * In such a case it is the responsibility of the parse functions to
 * store appropriate error information.
 */
typedef void (*error_f)(void *private, int line, const char *parsermsg);

/*
 * Function pointers called by the parser to notify consumer about some parse
 * event.  If the consumer is not interested in a specific event, the function
 * pointer should be set to NULL.
 * Every function gets a pointer to a private object that is opaque to the
 * parser.
 */
struct parsefuncs {
    ockversion_f  version;
    eol_f         eol;
    begin_slot_f  begin_slot;
    end_slot_f    end_slot;
    key_str_f     key_str;
    key_vers_f    key_vers;
    eolcomment_f  eolcomment;
    error_f       parseerror;
};

extern const char *keyword_token_to_str(int tok);

/*
 * Load and parse a configuration file via the given parser functions
 * and parser private data.
 * \return  0 on success,
 *         -1 if \c configfile could not be opened for reading,
 *          1 if parsing ended with errors.
 */
extern int load_and_parse(const char *configfile,
                          struct parsefuncs *funcs, void *private);

#endif
