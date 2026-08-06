/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* (C) COPYRIGHT Google Inc. 2013 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "slotmgr.h"
#include "log.h"
#include "pkcsslotd.h"

void PopulateCKInfo(CK_INFO_PTR_64 ckinf)
{
    CK_VERSION_PTR ckver;
    char *package_version_tmp;
    char *tok_str;
    CK_BYTE lib_major;
    CK_BYTE lib_minor;

    ckver = &(ckinf->cryptokiVersion);

    ckver->major = CRYPTOKI_API_MAJOR_V;
    ckver->minor = CRYPTOKI_API_MINOR_V;

    memset(ckinf->manufacturerID, ' ', sizeof(ckinf->manufacturerID));
    memset(ckinf->libraryDescription, ' ', sizeof(ckinf->libraryDescription));

    memcpy(ckinf->manufacturerID, MFG, strlen(MFG));
    memcpy(ckinf->libraryDescription, LIB, strlen(LIB));

    ckver = &(ckinf->libraryVersion);

    ckver->major = LIB_MAJOR_V;
    ckver->minor = LIB_MINOR_V;

#ifdef PACKAGE_VERSION
    package_version_tmp = malloc(strlen(PACKAGE_VERSION) + 1);
    if (package_version_tmp) {
        strcpy(package_version_tmp, PACKAGE_VERSION);
        tok_str = strtok(package_version_tmp, ".");
        if (tok_str) {
            lib_major = (CK_BYTE) atoi(tok_str);
            tok_str = strtok(NULL, ".");
            if (tok_str) {
                lib_minor = (CK_BYTE) atoi(tok_str);
                ckver->major = lib_major;
                ckver->minor = lib_minor;
            }
        }
        free(package_version_tmp);
    }
#endif

}

void PopulateSlotInfo(Slot_Info_t_64 *slot_info, unsigned int *processed)
{
    CK_SLOT_ID id;
    unsigned int slot_count = 0;

    /*
     *  populate the Slot entries...
     */

    for (id = 0; id < NUMBER_SLOTS_MANAGED; id++) {

        if (sinfo[id].present == FALSE) {
            /* skip empty slots and just note the slot number */
            slot_info[id].slot_number = id;
        } else {
            slot_info[id] = sinfo[id];
            slot_count++;
        }
    }
    *processed = slot_count;
}
