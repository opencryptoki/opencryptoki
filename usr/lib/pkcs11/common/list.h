/*
 * Very small linked list implementation.
 *
 * For simplicity and portability it doesn't use GCC extensions and sticks with
 * C89. That means there's no hidden variable declaration or type inference
 * inside the macros.
 */

#ifndef _LIST_H_
#define _LIST_H_

#include <stddef.h> /* for offsetof */

/*
 * Typedefs for lists and list entries.
 *
 * List entry should be defined as a member in an application-specific
 * structure.
 */
typedef struct _list list_t;
typedef struct _list_entry list_entry_t;

struct _list {
	list_entry_t *head;
	list_entry_t *tail;
};

struct _list_entry {
	list_entry_t *next;
	list_entry_t *prev;
	list_t *list;
};

/* A helper macro */
#ifndef container_of
#define container_of(_pt, _type, _field) \
	((_type *) (!(_pt) ? NULL : (((char *) (_pt)) - offsetof(_type, _field))))
#endif

/*
 * Macro to iterate over a list.
 *
 * It can *NOT* be used to remove entries while iterating.
 *
 */
#define for_each_list_entry(_head, _type, _var, _field) \
	for (_var = container_of((_head)->head, _type, _field); \
			(_var) && &((_var)->_field); \
			_var = container_of((_var)->_field.next, _type, _field))

/*
 * Similar to for_each_list_entry but it's possible to remove an entry while
 * iterating.
 *
 * It uses an additional list_entry_t* to hold the value of the next element.
 */
#define for_each_list_entry_safe(_head, _type, _var, _field, _next) \
	for (_var = container_of((_head)->head, _type, _field); \
			(_var) && &((_var)->_field) && \
			((_next = (_var)->_field.next) || 1); \
			_var = container_of(_next, _type, _field))

/*
 * Assignment initialization macro.
 */
#define LIST_INIT() \
	{ NULL, NULL };

/*
 * Initialize a list.
 */
static inline void
list_init(list_t *list)
{
	list->head = list->tail = NULL;
}

static inline int
list_is_empty(list_t *list)
{
	return (list->head == NULL);
}

/*
 * Insert a element at the head.
 */
static inline void
list_insert_head(list_t *list, list_entry_t *new)
{
	if (!list->head) {
		new->next = new->prev = NULL;
		list->head = list->tail = new;
	} else {
		new->prev = NULL;
		new->next = list->head;
		list->head->prev = new;
		list->head = new;
	}
	new->list = list;
}

/*
 * Insert a element at the end.
 */
static inline void
list_insert_tail(list_t *list, list_entry_t *new)
{
	if (!list->tail) {
		new->next = new->prev = NULL;
		list->head = list->tail = new;
	} else {
		new->next = NULL;
		new->prev = list->tail;
		list->tail->next = new;
		list->tail = new;
	}
	new->list = list;
}

/*
 * Remove an element.
 */
static inline void
list_remove(list_entry_t *entry)
{
	list_t *list = entry->list;

	if (list->head == entry)
		list->head = entry->next;

	if (list->tail == entry)
		list->tail = entry->prev;

	if (entry->next)
		entry->next->prev = entry->prev;

	if (entry->prev)
		entry->prev->next = entry->next;
}

#endif
