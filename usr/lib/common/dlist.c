/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include "dlist.h"
#include "host_defs.h"
#include "h_extern.h"


// Function:  dlist_add_as_first()
//
// Adds the specified node to the start of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *dlist_add_as_first(DL_NODE *list, void *data)
{
    DL_NODE *node = NULL;

    if (!data)
        return list;

    node = (DL_NODE *) malloc(sizeof(DL_NODE));
    if (!node)
        return NULL;

    node->data = data;
    node->prev = NULL;
    node->next = list;
    if (list)
        list->prev = node;

    return node;
}

// Function:  dlist_add_as_last()
//
// Adds the specified node to the end of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *dlist_add_as_last(DL_NODE *list, void *data)
{
    DL_NODE *node = NULL;

    if (!data)
        return list;

    node = (DL_NODE *) malloc(sizeof(DL_NODE));
    if (!node)
        return NULL;

    node->data = data;
    node->next = NULL;

    if (!list) {
        node->prev = NULL;
        return node;
    } else {
        DL_NODE *temp = dlist_get_last(list);
        temp->next = node;
        node->prev = temp;

        return list;
    }
}

// Function:  dlist_find()
//
DL_NODE *dlist_find(DL_NODE *list, void *data)
{
    DL_NODE *node = list;

    while (node && node->data != data)
        node = node->next;

    return node;
}

// Function:  dlist_get_first()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *dlist_get_first(DL_NODE *list)
{
    DL_NODE *temp = list;

    if (!list)
        return NULL;

    while (temp->prev != NULL)
        temp = temp->prev;

    return temp;
}

// Function:  dlist_get_last()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *dlist_get_last(DL_NODE *list)
{
    DL_NODE *temp = list;

    if (!list)
        return NULL;

    while (temp->next != NULL)
        temp = temp->next;

    return temp;
}

//
//
CK_ULONG dlist_length(DL_NODE *list)
{
    DL_NODE *temp = list;
    CK_ULONG len = 0;

    while (temp) {
        len++;
        temp = temp->next;
    }

    return len;
}

//
//
DL_NODE *dlist_next(DL_NODE *node)
{
    if (!node)
        return NULL;

    return node->next;
}

//
//
DL_NODE *dlist_prev(DL_NODE *node)
{
    if (!node)
        return NULL;

    return node->prev;
}

//
//
void dlist_purge(DL_NODE *list)
{
    DL_NODE *node;

    if (!list)
        return;

    do {
        node = list->next;
        free(list);
        list = node;
    } while (list);
}

// Function:  dlist_remove_node()
//
// Attempts to remove the specified node from the list.  The caller is
// responsible for freeing the data associated with the node prior to
// calling this routine
//
DL_NODE *dlist_remove_node(DL_NODE *list, DL_NODE *node)
{
    DL_NODE *temp = list;

    if (!list || !node)
        return NULL;

    // special case:  removing head of the list
    //
    if (list == node) {
        temp = list->next;
        if (temp)
            temp->prev = NULL;

        free(list);
        return temp;
    }
    // we have no guarantee that the node is in the list
    // so search through the list to find it
    //
    while ((temp != NULL) && (temp->next != node))
        temp = temp->next;

    if (temp != NULL) {
        DL_NODE *next = node->next;

        temp->next = next;
        if (next)
            next->prev = temp;

        free(node);
    }

    return list;
}
