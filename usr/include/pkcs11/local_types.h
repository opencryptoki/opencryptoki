 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#ifndef __LOCAL_TYPES
#define __LOCAL_TYPES

typedef unsigned char  uint8;

typedef unsigned short uint16;
// typedef short          int16;

typedef unsigned int   uint32;
// typedef int            int32;


#define BT_FLAG_FREE	1

/* Binary tree node
 * - 20 bytes on 32bit platform
 * - 40 bytes on 64bit platform
 */
struct btnode
{
	struct btnode *left;
	struct btnode *right;
	struct btnode *parent;
	unsigned long flags;
	void *value;
};

/* Binary tree root */
struct btree
{
	struct btnode *free_list;
	struct btnode *top;
	unsigned long size;
	unsigned long free_nodes;
};

typedef struct _STDLL_TokData_t STDLL_TokData_t;

struct btnode *bt_get_node(struct btree *t, unsigned long node_num);
void *bt_get_node_value(struct btree *t, unsigned long node_num);
int bt_is_empty(struct btree *t);
void bt_for_each_node(STDLL_TokData_t *, struct btree *t,
		      void (*)(STDLL_TokData_t *, void *, unsigned long, void *), void *);
unsigned long bt_nodes_in_use(struct btree *t);
unsigned long bt_node_add(struct btree *t, void *value);
struct btnode *bt_node_free(struct btree *t, unsigned long node_num,
			    void (*delete_func)(void *));
struct btnode *bt_node_free_(STDLL_TokData_t *tokdata, struct btree *t,
			     unsigned long node_num,
			     void (*delete_func)(STDLL_TokData_t *, void *));
void bt_destroy(struct btree *t, void (*func)(void *));

#endif
