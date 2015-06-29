
/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
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

#include "pkcs11types.h"
#include "local_types.h"
#include "trace.h"

#define GET_NODE_HANDLE(n)	get_node_handle(n, 1)
#define TREE_DUMP(t)		tree_dump((t)->top, 0)

/*
 * bt_get_node
 *
 * Return a node of the tree @t with position @node_num. If the node has been freed
 * or doesn't exist, return NULL
 */
struct btnode *
bt_get_node(struct btree *t, unsigned long node_num)
{
	struct btnode *temp = t->top;
	unsigned long i;

	if (!node_num || node_num > t->size)
		return NULL;
	if (node_num == 1) {
		temp = t->top;
		goto done;
	}

	i = node_num;
	while (i != 1) {
		if (i & 1) {
			temp = temp->right;	// If the bit is a 1, traverse right
		} else {
			temp = temp->left;	// If the bit is a zero, traverse left
		}

		i >>= 1;
	}
done:
	return ((temp->flags & BT_FLAG_FREE) ? NULL : temp);
}

void *
bt_get_node_value(struct btree *t, unsigned long node_num)
{
	struct btnode *n = bt_get_node(t, node_num);

	return ((n) ? n->value : NULL);
}

/* create a new node and set @parent_ptr to its location */
static struct btnode *
node_create(struct btnode **child_ptr, struct btnode *parent_ptr, void *value)
{
	struct btnode *node = malloc(sizeof(struct btnode));

	if (!node) {
		TRACE_ERROR("malloc of %lu bytes failed", sizeof(struct btnode));
		return NULL;
	}

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
 * Recursively construct a node's handle by tracing its path back to the root node
 */
static unsigned long
get_node_handle(struct btnode *node, unsigned long handle_so_far)
{
	if (!node->parent)
		return handle_so_far;
	else if (node->parent->left == node)
		return get_node_handle(node->parent, handle_so_far << 1);
	else
		return get_node_handle(node->parent, (handle_so_far << 1) + 1);
}

/* return node number (handle) of newly created node, or 0 for failure */
unsigned long
bt_node_add(struct btree *t, void *value)
{
	struct btnode *temp = t->top;
	unsigned long new_node_index;

	if (!temp) {
		/* no root node yet exists, create it */
		t->size = 1;
		if (!node_create(&t->top, NULL, value)) {
			TRACE_ERROR("Error creating node");
			return 0;
		}

		return 1;
	} else if (t->free_list) {
		/* there's a node on the free list, use it instead of mallocing new */
		temp = t->free_list;
		t->free_list = temp->value;
		temp->value = value;
		temp->flags &= (~BT_FLAG_FREE);
		t->free_nodes--;
		new_node_index = GET_NODE_HANDLE(temp);
		return new_node_index;
	}


	new_node_index = t->size + 1;

	while (new_node_index != 1) {
		if (new_node_index & 1) {
			if (!temp->right) {
				if (!(node_create(&temp->right, temp, value))) {
					TRACE_ERROR("node_create failed");
					return 0;
				}

				break;
			} else {
				temp = temp->right;	// If the bit is a 1, traverse right
			}
		} else {
			if (!temp->left) {
				if (!(node_create(&temp->left, temp, value))) {
					TRACE_ERROR("node_create failed");
					return 0;
				}

				break;
			} else {
				temp = temp->left;	// If the bit is a zero, traverse left
			}
		}

		new_node_index >>= 1;
	}

	t->size++;

	return t->size;
}

void
tree_dump(struct btnode *n, int depth)
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

	tree_dump(n->left, depth+1);
	tree_dump(n->right, depth+1);
}

/*
 * bt_node_free
 *
 * Move @node_num in tree @t to the free list, calling @delete_func on its value first.
 *
 * Note that bt_get_node will return NULL if the node is already on the free list, so
 * no double freeing can occur
 */
struct btnode *
bt_node_free(struct btree *t, unsigned long node_num, void (*delete_func)(void *))
{
	struct btnode *node = bt_get_node(t, node_num);

	if (node) {
		if (delete_func)
			(*delete_func)(node->value);
		node->flags |= BT_FLAG_FREE;

		/* add node to the free list, which is chained by using the value pointer */
		node->value = t->free_list;
		t->free_list = node;
		t->free_nodes++;
	}

	return node;
}

/* bt_is_empty
 *
 * return 0 if binary tree has at least 1 node in use, !0 otherwise
 */
int bt_is_empty(struct btree *t)
{
	return (t->free_nodes == t->size);
}

/* bt_nodes_in_use
 *
 * return the number of nodes in the binary tree that are not free'd
 */
unsigned long bt_nodes_in_use(struct btree *t)
{
	return (t->size - t->free_nodes);
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
void
bt_for_each_node(struct btree *t, void (*func)(void *p1, unsigned long p2, void *p3), void *p3)
{
	unsigned int i;
	struct btnode *node;

	for (i = 1; i < t->size+1; i++) {
		node = bt_get_node(t, i);

		if (node) {
			(*func)(node->value, i, p3);
		}
	}
}

/* bt_destroy
 *
 * Walk a binary tree backwards (largest index to smallest), deleting nodes along the way.
 * Call @func on node->value before freeing the node.
 */
void
bt_destroy(struct btree *t, void (*func)(void *))
{
	unsigned long i;
	struct btnode *temp;

	while (t->size) {
		temp = t->top;
		i = t->size;
		while (i != 1) {
			if (i & 1) {
				temp = temp->right;	// If the bit is a 1, traverse right
			} else {
				temp = temp->left;	// If the bit is a zero, traverse left
			}

			i >>= 1;
		}

		/*
		 * The value pointed by value in a node marked as freed points
		 * to the next node element in free_list and it shouldn't be
		 * freed here because the loop will iterate through each node,
		 * freed or not.
		 */
		if (func && !(temp->flags & BT_FLAG_FREE))
			(*func)(temp->value);

		free(temp);
		t->size--;
	}

	/* the tree is gone now, clear all the other variables */
	t->top = NULL;
	t->free_list = NULL;
	t->free_nodes = 0;
}

