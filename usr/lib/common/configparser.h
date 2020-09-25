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

struct config_parse_env {
    Slot_Info_t_64 sinfo[NUMBER_SLOTS_MANAGED];
    unsigned int NumberSlotsInDB;
    /* TODO: Should we count the number of errors during parsing? */
};

int load_and_parse(const char *configfile, struct config_parse_env *env);

#endif
