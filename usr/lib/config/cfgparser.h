/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef CFGPARSER_H
#define CFGPARSER_H

#include <stdio.h>
#include "configuration.h"

typedef void (*error_hook_f)(int line, int col, const char *msg);

int parse_configlib_file(FILE *conf, struct ConfigBaseNode **res,
                         error_hook_f error_hook, int trackComments);

#endif
