/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */



#ifndef _DLIST_H_
#define _DLIST_H_

#include "pkcs11types.h"
#include "defs.h"

// linked-list routines
//
DL_NODE *dlist_add_as_first(DL_NODE *list, void *data);
DL_NODE *dlist_add_as_last(DL_NODE *list, void *data);
DL_NODE *dlist_find(DL_NODE *list, void *data);
DL_NODE *dlist_get_first(DL_NODE *list);
DL_NODE *dlist_get_last(DL_NODE *list);
CK_ULONG dlist_length(DL_NODE *list);
DL_NODE *dlist_next(DL_NODE *list);
DL_NODE *dlist_prev(DL_NODE *list);
void dlist_purge(DL_NODE *list);
DL_NODE *dlist_remove_node(DL_NODE *list, DL_NODE *node);

#endif
