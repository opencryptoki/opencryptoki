/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * btree.c
 * Author: Kent Yoder <yoder1@us.ibm.com>
 *
 * v1 Binary tree functions 4/5/2011
 *
 */


#include <stdio.h>
#include <malloc.h>
#include <pthread.h>

#include "pkcs11types.h"
#include "local_types.h"
#include "trace.h"

#define GET_NODE_HANDLE(n) get_node_handle(n, 1)
#define TREE_DUMP(t)  tree_dump((t)->top, 0)

/*
 * __bt_get_node() - Low level function, needs proper locking before invocation.
 */
static struct btnode *__bt_get_node(struct btree *t, unsigned long node_num)
{
    struct btnode *temp;
    unsigned long i;

    temp = t->top;

    if (!node_num || node_num > t->size)
        return NULL;

    if (node_num == 1) {
        temp = t->top;
        return (temp->flags & BT_FLAG_FREE) ? NULL : temp;
    }

    i = node_num;
    while (i != 1) {
        if (i & 1) {
            /* If the bit is 1, traverse right */
            temp = temp->right;
        } else {
            /* If the bit is 0, traverse left */
            temp = temp->left;
        }
        i >>= 1;
    }

    return (temp->flags & BT_FLAG_FREE) ? NULL : temp;
}

/*
 * bt_get_node
 *
 * Return a node of the tree @t with position @node_num. If the node has been
 * freed or doesn't exist, return NULL
 */
struct btnode *bt_get_node(struct btree *t, unsigned long node_num)
{
    struct btnode *temp;

    if (pthread_mutex_lock(&t->mutex)) {
        TRACE_ERROR("BTree Lock failed.\n");
        return NULL;
    }

    temp = __bt_get_node(t, node_num);

    pthread_mutex_unlock(&t->mutex);

    return temp;
}

/*
 * Get the value of the specified node. Returns NULL if the node has been
 * deleted. Increases the value's reference counter to prevent it from being
 * freed while in use. The caller needs to call bt_put_node_value() to
 * decrease the reference counter when the value is no longer used.
 */
void *bt_get_node_value(struct btree *t, unsigned long node_num)
{
    struct btnode *n;
    void *v;
    unsigned long ref;

#ifndef DEBUG
    UNUSED(ref);
#endif

    if (pthread_mutex_lock(&t->mutex)) {
        TRACE_ERROR("BTree Lock failed.\n");
        return NULL;
    }

    /*
     * Get the value within the locked block, to ensure that the node
     * is not deleted after it was obtained via bt_get_node, but before the
     * value is obtained from the node. For a deleted node, the node->value
     * points to another node in the free list.
     */
    n = __bt_get_node(t, node_num);
    v = ((n) ? n->value : NULL);

    if (v != NULL) {
        ref = __sync_add_and_fetch(&((struct bt_ref_hdr *)v)->ref, 1);

        TRACE_DEBUG("bt_get_node_value: Btree: %p Value: %p Ref: %lu\n",
                    (void *)t, v, ref);
    }

    pthread_mutex_unlock(&t->mutex);
    return v;
}

/*
 * Decrease the node values reference counter.
 * If the reference counter reaches zero, then the btree's delete callback
 * function is called to delete the value.
 * Returns 1 of the value has been deleted, 0 otherwise.
 */
int bt_put_node_value(struct btree *t, void *value)
{
    int rc = 0;
    unsigned long ref;

    if (value == NULL)
        return 0;

    if (((struct bt_ref_hdr *)value)->ref > 0) {
        ref = __sync_sub_and_fetch(&((struct bt_ref_hdr *)value)->ref, 1);

        TRACE_DEBUG("bt_put_node_value: Btree: %p Value: %p Ref: %lu\n",
                    (void *)t, value, ((struct bt_ref_hdr *)value)->ref);
    } else {
        TRACE_WARNING("bt_put_node_value: BTree: %p Value %p Ref already 0.\n",
                      (void *)t, value);
        ref = 0;
    }

    if (ref == 0 && t->delete_func) {
         TRACE_DEBUG("delete_func: Btree: %p Value: %p\n", (void *)t, value);

         t->delete_func(value);
         rc = 1;
    }

    return rc;
}

/* create a new node and set @parent_ptr to its location */
static struct btnode *node_create(struct btnode **child_ptr,
                                  struct btnode *parent_ptr, void *value)
{
    struct btnode *node = malloc(sizeof(struct btnode));

    if (!node)
        return NULL;

    node->left = node->right = NULL;
    node->flags = 0;
    node->value = value;
    *child_ptr = node;
    node->parent = parent_ptr;

    return node;
}

/*
 * get_node_handle
 *
 * Recursively construct a node's handle by tracing its path back to the root
 * node
 */
static unsigned long get_node_handle(struct btnode *node,
                                     unsigned long handle_so_far)
{
    if (!node->parent)
        return handle_so_far;
    else if (node->parent->left == node)
        return get_node_handle(node->parent, handle_so_far << 1);
    else
        return get_node_handle(node->parent, (handle_so_far << 1) + 1);
}

/*
 * Return node number (handle) of newly created node, or 0 for failure.
 * Value must start with struct bt_ref_hdr to maintain the reference counter.
 * The reference counter is initialized to 1.
 */
unsigned long bt_node_add(struct btree *t, void *value)
{
    struct btnode *temp;
    unsigned long new_node_index;

    if (pthread_mutex_lock(&t->mutex)) {
        TRACE_ERROR("BTree Lock failed.\n");
        return 0;
    }

    ((struct bt_ref_hdr *)value)->ref = 1;

    TRACE_DEBUG("bt_node_add: Btree: %p Value: %p Ref: %lu\n", (void *)t, value,
                ((struct bt_ref_hdr *)value)->ref);

    temp = t->top;

    if (!temp) {                /* no root node yet exists, create it */
        t->size = 1;
        if (!node_create(&t->top, NULL, value)) {
            pthread_mutex_unlock(&t->mutex);
            return 0;
        }

        pthread_mutex_unlock(&t->mutex);
        return 1;
    } else if (t->free_list) {
        /* there's a node on the free list,
         * use it instead of mallocing new
         */
        temp = t->free_list;
        t->free_list = temp->value;
        temp->value = value;
        temp->flags &= (~BT_FLAG_FREE);
        t->free_nodes--;
        new_node_index = GET_NODE_HANDLE(temp);
        pthread_mutex_unlock(&t->mutex);
        return new_node_index;
    }

    new_node_index = t->size + 1;

    while (new_node_index != 1) {
        if (new_node_index & 1) {
            if (!temp->right) {
                if (!(node_create(&temp->right, temp, value))) {
                    pthread_mutex_unlock(&t->mutex);
                    return 0;
                }
                break;
            } else {
                /* If the bit is 1, traverse right */
                temp = temp->right;
            }
        } else {
            if (!temp->left) {
                if (!(node_create(&temp->left, temp, value))) {
                    pthread_mutex_unlock(&t->mutex);
                    return 0;
                }
                break;
            } else {
                /* If the bit is 0, traverse left */
                temp = temp->left;
            }
        }

        new_node_index >>= 1;
    }

    t->size++;
    new_node_index = t->size;

    pthread_mutex_unlock(&t->mutex);
    return new_node_index;
}

void tree_dump(struct btnode *n, int depth)
{
    int i;

    if (!n)
        return;

    for (i = 0; i < depth; i++)
        printf("  ");

    if (n->flags & BT_FLAG_FREE)
        printf("`- (deleted node)\n");
    else
        printf("`- %p\n", n->value);

    tree_dump(n->left, depth + 1);
    tree_dump(n->right, depth + 1);
}

/*
 * bt_node_free
 *
 * Move @node_num in tree @t to the free list, decrease the value's reference
 * counter, and if the reference counter reaches zero, calls the dbtree's
 * delete callback on its value.
 * Return the deleted value. Note that if the callback routine frees
 * the value, then the returned value might have already been freed. You still
 * can use it as indication that it found the node_num in the tree and moved
 * it to the free list.
 *
 * Note that bt_get_node will return NULL if the node is already on the free
 * list, so no double freeing can occur
 */
void *bt_node_free(struct btree *t, unsigned long node_num,
                   int put_value)
{
    struct btnode *node;
    void *value = NULL;

    if (pthread_mutex_lock(&t->mutex)) {
        TRACE_ERROR("BTree Lock failed.\n");
        return NULL;
    }

    node = __bt_get_node(t, node_num);

    if (node) {
        /*
         * Need to get the node value within the locked block,
         * otherwise the node might be deleted concurrently before the
         * value was obtained from the node.
         */
        value = node->value;

        node->flags |= BT_FLAG_FREE;

        /* add node to the free list,
         * which is chained by using
         * the value pointer
         */
        node->value = t->free_list;
        t->free_list = node;
        t->free_nodes++;

        TRACE_DEBUG("bt_node_free: Btree: %p Value: %p Ref: %lu\n", (void *)t,
                    value, ((struct bt_ref_hdr *)value)->ref);
    }

    pthread_mutex_unlock(&t->mutex);

    if (value && put_value)
        bt_put_node_value(t, value);

    return value;
}

/* bt_is_empty
 *
 * return 0 if binary tree has at least 1 node in use, !0 otherwise
 */
int bt_is_empty(struct btree *t)
{
    CK_RV rc;

    if (pthread_mutex_lock(&t->mutex))
        return 0;

    rc = (t->free_nodes == t->size);

    pthread_mutex_unlock(&t->mutex);

    return rc;
}

/* bt_nodes_in_use
 *
 * return the number of nodes in the binary tree that are not free'd
 */
unsigned long bt_nodes_in_use(struct btree *t)
{
    CK_RV rc;

    if (pthread_mutex_lock(&t->mutex)) {
        TRACE_ERROR("BTree Lock failed.\n");
        return -1;
    }

    rc = (t->size - t->free_nodes);

    pthread_mutex_unlock(&t->mutex);

    return rc;
}

/* bt_for_each_node
 *
 * For each non-free'd node in the tree, run @func on it
 *
 * @func:
 *  p1 is the node's value
 *  p2 is the node's handle
 *  p3 is passed through this function for the caller
 */
void bt_for_each_node(STDLL_TokData_t *tokdata, struct btree *t, void (*func)
                      (STDLL_TokData_t *tokdata, void *p1, unsigned long p2,
                      void *p3), void *p3)
{
    unsigned int i;
    void *value;

    for (i = 1; i < t->size + 1; i++) {
        /*
         * Get the node value, not the node itself. This ensures that we either
         * get the value from a valid node, or NULL in case of a deleted node.
         * If we would get the node and then get the value from it without
         * being in the locked block, the node could have been deleted after
         * the node was obtained, but before the value was obtained.
         */
        value = bt_get_node_value(t, i);

        if (value) {
            (*func) (tokdata, value, i, p3);

            bt_put_node_value(t, value);
            value = NULL;
        }
    }
}

/* bt_destroy
 *
 * Walk a binary tree backwards (largest index to smallest), deleting nodes
 * along the way.
 * Call the btree's delete callback on node->value before freeing the node.
 */
void bt_destroy(struct btree *t)
{
    unsigned long i;
    struct btnode *temp;

    if (pthread_mutex_lock(&t->mutex)) {
        TRACE_ERROR("BTree Lock failed.\n");
        return;
    }

    while (t->size) {
        temp = t->top;
        i = t->size;
        while (i != 1) {
            if (i & 1) {
                /* If the bit is 1, traverse right */
                temp = temp->right;
            } else {
                /* If the bit is 0, traverse left */
                temp = temp->left;
            }
            i >>= 1;
        }

        /*
         * The value pointed by value in a node marked as freed points
         * to the next node element in free_list and it shouldn't be
         * freed here because the loop will iterate through each node,
         * freed or not.
         */
        if (t->delete_func && !(temp->flags & BT_FLAG_FREE)) {

            TRACE_DEBUG("bt_destroy: Btree: %p Value: %p Ref: %lu\n", (void *)t,
                        temp->value, ((struct bt_ref_hdr *)temp->value)->ref);

            t->delete_func(temp->value);
        }

        free(temp);
        t->size--;
    }

    /* the tree is gone now, clear all the other variables */
    t->top = NULL;
    t->free_list = NULL;
    t->free_nodes = 0;
    t->delete_func = NULL;

    pthread_mutex_unlock(&t->mutex);
    pthread_mutex_destroy(&t->mutex);
}

/* bt_init
 *
 * Initialize a btree with a delete callback function that is used to delete
 * values during bt_node_free() and bt_destroy().
 */
CK_RV bt_init(struct btree *t, void (*delete_func)(void *))
{
    pthread_mutexattr_t attr;

    t->free_list = NULL;
    t->top = NULL;
    t->size = 0;
    t->free_nodes = 0;
    t->delete_func = delete_func;

    /*
     * Need a recursive mutex, because btree callback functions may call
     * btree functions again
     */
    if (pthread_mutexattr_init(&attr) != 0) {
        TRACE_ERROR("pthread_mutexattr_init failed.\n");
        return CKR_CANT_LOCK;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        TRACE_ERROR("pthread_mutexattr_settype failed.\n");
        return CKR_CANT_LOCK;
    }
    if (pthread_mutex_init(&t->mutex, &attr) != 0) {
        TRACE_ERROR("pthread_mutex_init failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}
