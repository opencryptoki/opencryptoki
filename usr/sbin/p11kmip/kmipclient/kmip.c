/*
 * COPYRIGHT (c) International Business Machines Corp. 2021-2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "kmip.h"
#include "utils.h"

void __attribute__ ((constructor)) kmip_init(void);
void __attribute__ ((destructor)) kmip_exit(void);

/**
 * Constructs a new KMIP node with the specified tag and type, and an optional
 * name. The newly allocated node has a reference count of 1.
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param type              the type of the new node
 *
 * @returns the allocated node, or NULL in case of an error
 */
static struct kmip_node *kmip_node_new(enum kmip_tag tag, const char *name,
				       enum kmip_type type)
{
	struct kmip_node *node;

	node = calloc(1, sizeof(struct kmip_node));
	if (node == NULL)
		return NULL;

	node->ref_count = 1;
	node->tag = tag;
	node->type = type;

	if (name != NULL) {
		node->name = strdup(name);
		if (node->name == NULL) {
			free(node);
			return NULL;
		}
	}

	return node;
}

/**
 * Returns the tag of a KMIP node
 *
 * @param node              the KMIP node
 *
 * @returns the tag
 */
enum kmip_tag kmip_node_get_tag(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	return node->tag;
}

/**
 * Returns the type of a KMIP node
 *
 * @param node              the KMIP node
 *
 * @returns the type
 */
enum kmip_type kmip_node_get_type(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	return node->type;
}

/**
 * Returns the name of a KMIP node
 *
 * @param node              the KMIP node
 *
 * @returns a copy of the name. The caller must free the returnd string.
 */
char *kmip_node_get_name(const struct kmip_node *node)
{
	if (node == NULL)
		return NULL;

	if (node->name == NULL)
		return NULL;

	return strdup(node->name);
}

/**
 * Constructs a new KMIP node of type structure with the specified tag, and an
 * optional name, and the elements. The reference count of each added element is
 * increased.
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param num_elements      the number of elements to add
 * @param elements          the array elements to add.
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_structure(enum kmip_tag tag, const char *name,
					  unsigned int num_elements,
					  struct kmip_node **elements)
{
	struct kmip_node *node;
	int rc;

	node = kmip_node_new(tag, name, KMIP_TYPE_STRUCTURE);
	if (node == NULL)
		return NULL;

	rc = kmip_node_add_structure_elements(node, num_elements, elements);
	if (rc != 0) {
		kmip_node_free(node);
		return NULL;
	}

	return node;
}

/**
 * Constructs a new KMIP node of type structure with the specified tag, and an
 * optional name, and the elements. The reference count of each added element is
 * increased.
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param num_elements      the number of elements following as variable args
 * @param <element ...>     the elements to add. Elements may be NULL, those
 *                          are skipped
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_structure_va(enum kmip_tag tag,
					     const char *name,
					     unsigned int num_elements, ...)
{
	struct kmip_node *node, **elements = NULL;
	unsigned int i;
	va_list ap;

	if (num_elements > 0) {
		elements = calloc(num_elements, sizeof(struct kmip_node *));
		if (elements == NULL)
			return NULL;
	}

	va_start(ap, num_elements);
	for (i = 0; i < num_elements; i++)
		elements[i] = va_arg(ap, struct kmip_node *);
	va_end(ap);

	node = kmip_node_new_structure(tag, name, num_elements, elements);

	if (elements != NULL)
		free(elements);

	return node;
}

/**
 * Add an element to a KMIP node (which must be of type KMIP_TYPE_STRUCTURE).
 * The element is added as the last element. The reference count of the added
 * element is increased.
 *
 * @param node              the structure node to add the element to
 * @param element           the element to add
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_node_add_structure_element(struct kmip_node *node,
				    struct kmip_node *element)
{
	if (node == NULL ||  element == NULL)
		return -EINVAL;

	return kmip_node_add_structure_elements(node, 1, &element);
}

/**
 * Add elements to a KMIP node (which must be of type KMIP_TYPE_STRUCTURE).
 * The elements are added after the last element. The reference count of the
 * added elements is increased.
 *
 * @param node              the structure node to add the element to
 * @param num_elements      the number of elements to add
 * @param elements          the array elements to add
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_node_add_structure_elements(struct kmip_node *node,
				     unsigned int num_elements,
				     struct kmip_node **elements)
{
	struct kmip_node *element, *last;
	unsigned int i;

	if (node == NULL || (num_elements > 0 && elements == NULL))
		return -EINVAL;

	if (node->type != KMIP_TYPE_STRUCTURE)
		return -EINVAL;

	if (node->structure_value == NULL) {
		last = NULL;
	} else {
		last = node->structure_value;
		while (last->next != NULL)
			last = last->next;
	}

	for (i = 0; i < num_elements; i++) {
		element = elements[i];
		if (element == NULL)
			continue;

		kmip_node_upref(element);

		element->parent = node;
		element->next = NULL;

		if (last == NULL)
			node->structure_value = element;
		else
			last->next = element;

		last = element;
	}

	return 0;
}

/**
 * Returns the number of elements of a KMIP node of type structure
 *
 * @param node              the KMIP node
 *
 * @returns the number of elements, or -1 if  the node is not of type structure
 */
unsigned int kmip_node_get_structure_element_count(const struct kmip_node *node)
{
	struct kmip_node *element;
	unsigned int i;

	if (node == NULL)
		return -1;

	if (node->type != KMIP_TYPE_STRUCTURE)
		return -1;

	element = node->structure_value;
	for (i = 0; element != NULL; i++)
		element = element->next;

	return i;
}

/**
 * Returns an element of a KMIP node of type structure
 *
 * @param node              the KMIP node
 * @param index             the index of the element to return
 *
 * @returns the element or NULL if no element is available at the specified
 * index, or the node is not of type structure.
 * The reference count of the returned element is increased. The caller must
 * free the element via kmip_node_free() when no longer needed.
 */
struct kmip_node *kmip_node_get_structure_element_by_index(
					const struct kmip_node *node,
					unsigned int index)
{
	struct kmip_node *element;
	unsigned int i;

	if (node == NULL)
		return NULL;

	if (node->type != KMIP_TYPE_STRUCTURE)
		return NULL;

	element = node->structure_value;
	for (i = 0; i < index && element != NULL; i++)
		element = element->next;

	if (element != NULL)
		kmip_node_upref(element);

	return element;
}

/**
 * Returns the number of elements of a KMIP node of type structure of a
 * certain tag
 *
 * @param node              the KMIP node
 * @param tag               the tag to find
 *
 * @returns the number of elements, or -1 if  the node is not of type structure
 */
unsigned int kmip_node_get_structure_element_by_tag_count(
					const struct kmip_node *node,
					enum kmip_tag tag)
{
	struct kmip_node *element;
	unsigned int i;

	if (node == NULL)
		return -1;

	if (node->type != KMIP_TYPE_STRUCTURE)
		return -1;

	element = node->structure_value;
	for (i = 0; element != NULL; element = element->next) {
		if (element->tag != tag)
			continue;
		i++;
	}

	return i;
}

/**
 * Find a structure element by its tag. If multiple elements with the matching
 * tag are found, then the num'th one is returned.
 *
 * @param node              the structure node to find the elements in
 * @param tag               the tag to find
 * @param index             the index of elements with the same tag to return.
 *
 * @returns the element node, or NULL if no element with the tag was found.
 * The reference count of the returned element is increased. The caller must
 * free the element via kmip_node_free() when no longer needed.
 */
struct kmip_node *kmip_node_get_structure_element_by_tag(
					const struct kmip_node *node,
					enum kmip_tag tag, unsigned int index)
{
	struct kmip_node *e;

	if (node == NULL)
		return NULL;

	if (node->type != KMIP_TYPE_STRUCTURE)
		return NULL;

	e = node->structure_value;
	while (e != NULL) {
		if (e->tag == tag) {
			if (index == 0) {
				kmip_node_upref(e);
				return e;
			}
			index--;
		}
		e = e->next;
	}

	return NULL;
}

/**
 * Constructs a new KMIP node of type integer with the specified tag, and an
 * optional name, and the integer value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_integer(enum kmip_tag tag, const char *name,
					int32_t value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_INTEGER);
	if (node == NULL)
		return NULL;

	node->integer_value = value;
	node->length = sizeof(int32_t);
	return node;
}

/**
 * Returns the value of a KMIP node of type integer
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or 0 if the node is not of type integer
 */
int32_t kmip_node_get_integer(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	if (node->type != KMIP_TYPE_INTEGER)
		return 0;

	return node->integer_value;
}

/**
 * Constructs a new KMIP node of type long integer with the specified tag, and
 * an optional name, and the long integer value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_long(enum kmip_tag tag, const char *name,
				     int64_t value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_LONG_INTEGER);
	if (node == NULL)
		return NULL;

	node->long_value = value;
	node->length = sizeof(int64_t);
	return node;
}

/**
 * Returns the value of a KMIP node of type long integer
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or 0 if the node is not of type long integer
 */
int64_t kmip_node_get_long(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	if (node->type != KMIP_TYPE_LONG_INTEGER)
		return 0;

	return node->long_value;
}

/**
 * Constructs a new KMIP node of type big integer with the specified tag, and
 * an optional name, and the big integer value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value as OpenSSL BIGNUM (can be NULL)
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_bigint(enum kmip_tag tag, const char *name,
				       const BIGNUM *value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_BIG_INTEGER);
	if (node == NULL)
		return NULL;

	if (value != NULL) {
		node->big_integer_value = BN_dup(value);
		node->length = kmip_encode_bignum_length(value);
	}
	return node;
}

/**
 * Returns the value of a KMIP node of type big integer
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or NULL if the node is not of type big
 * integer, or no BIGNUM is set. The returned BIGNUM still belongs to the node,
 * and must not be freed by the caller. It is freed together with the node it
 * was obtained from.
 */
const BIGNUM *kmip_node_get_bigint(const struct kmip_node *node)
{
	if (node == NULL)
		return NULL;

	if (node->type != KMIP_TYPE_BIG_INTEGER)
		return NULL;

	return node->big_integer_value;
}

/**
 * Constructs a new KMIP node of type enumeration with the specified tag, and
 * an optional name, and the enumeration value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param enumeration       the enumeration value
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_enumeration(enum kmip_tag tag, const char *name,
					    uint32_t enumeration)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_ENUMERATION);
	if (node == NULL)
		return NULL;

	node->enumeration_value = enumeration;
	node->length = sizeof(uint32_t);
	return node;
}

/**
 * Returns the value of a KMIP node of type enumeration
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or 0 if the node is not of type enumeration
 */
uint32_t kmip_node_get_enumeration(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	if (node->type != KMIP_TYPE_ENUMERATION)
		return 0;

	return node->enumeration_value;
}

/**
 * Constructs a new KMIP node of type boolean with the specified tag, and
 * an optional name, and the boolean value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_boolean(enum kmip_tag tag, const char *name,
					bool value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_BOOLEAN);
	if (node == NULL)
		return NULL;

	node->boolean_value = value;
	node->length = sizeof(uint64_t);
	return node;
}

/**
 * Returns the value of a KMIP node of type boolean
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or 0 if the node is not of type boolean
 */
bool kmip_node_get_boolean(const struct kmip_node *node)
{
	if (node == NULL)
		return false;

	if (node->type != KMIP_TYPE_BOOLEAN)
		return false;

	return node->boolean_value;
}

/**
 * Constructs a new KMIP node of type text string with the specified tag, and
 * an optional name, and the text string value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value (can be NULL)
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_text_string(enum kmip_tag tag, const char *name,
					    const char *value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_TEXT_STRING);
	if (node == NULL)
		return NULL;

	if (value != NULL) {
		node->text_value = strdup(value);
		if (node->text_value == NULL) {
			free(node);
			return NULL;
		}
		node->length = strlen(value);
	}
	return node;
}

/**
 * Returns the value of a KMIP node of type text string
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or NULL if the node is not of type text
 * string or no string is set. The returned string still belongs to the node,
 * and must not be freed by the caller. It is freed together with the node it
 * was obtained from.
 */
const char *kmip_node_get_text_string(const struct kmip_node *node)
{
	if (node == NULL)
		return NULL;

	if (node->type != KMIP_TYPE_TEXT_STRING)
		return NULL;

	return node->text_value;
}

/**
 * Constructs a new KMIP node of type byte string with the specified tag, and
 * an optional name, and the byte string value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the byte string (can be NULL)
 * @param length            the length of the byte string
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_byte_string(enum kmip_tag tag, const char *name,
					    const unsigned char *value,
					    uint32_t length)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_BYTE_STRING);
	if (node == NULL)
		return NULL;

	if (value != NULL && length > 0) {
		node->bytes_value = malloc(length);
		if (node->bytes_value == NULL) {
			free(node);
			return NULL;
		}
		memcpy(node->bytes_value, value, length);
		node->length = length;
	}
	return node;
}

/**
 * Returns the value of a KMIP node of type byte string
 *
 * @param node              the KMIP node
 * @param length            On return, the length of the byte string
 *
 * @returns the value of the node, or NULL if the node is not of type byte
 * string or no string is set. The returned string still belongs to the node,
 * and must not be freed by the caller. It is freed together with the node it
 * was obtained from.
 */
const unsigned char *kmip_node_get_byte_string(const struct kmip_node *node,
					       uint32_t *length)
{
	if (node == NULL)
		return NULL;

	if (node->type != KMIP_TYPE_BYTE_STRING)
		return NULL;

	if (length != NULL)
		*length = node->length;
	return node->bytes_value;
}

/**
 * Constructs a new KMIP node of type date and time with the specified tag, and
 * an optional name, and the date and time value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_date_time(enum kmip_tag tag, const char *name,
					  int64_t value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_DATE_TIME);
	if (node == NULL)
		return NULL;

	node->date_time_value = value;
	node->length = sizeof(int64_t);
	return node;
}

/**
 * Returns the value of a KMIP node of type date and time
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or 0 if the node is not of type date and time
 */
int64_t kmip_node_get_date_time(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	if (node->type != KMIP_TYPE_DATE_TIME)
		return 0;

	return node->date_time_value;
}

/**
 * Constructs a new KMIP node of type interval with the specified tag, and
 * an optional name, and the interval value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_interval(enum kmip_tag tag, const char *name,
					 uint32_t value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_INTERVAL);
	if (node == NULL)
		return NULL;

	node->interval_value = value;
	node->length = sizeof(uint32_t);
	return node;
}

/**
 * Returns the value of a KMIP node of type interval
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or 0 if the node is not of type interval
 */
uint32_t kmip_node_get_interval(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	if (node->type != KMIP_TYPE_INTERVAL)
		return 0;

	return node->interval_value;
}

/**
 * Constructs a new KMIP node of type date and time extended with the specified
 * tag, and an optional name, and the date and time value
 *
 * @param tag               the tag of the new node
 * @param name              Optional: the name of the node (only used with JSON
 *                          or XML encoding). Can be NULL.
 * @param value             the value
 *
 * @returns the allocated node, or NULL in case of an error
 */
struct kmip_node *kmip_node_new_date_time_ext(enum kmip_tag tag,
					      const char *name,
					      int64_t value)
{
	struct kmip_node *node;

	node = kmip_node_new(tag, name, KMIP_TYPE_DATE_TIME_EXTENDED);
	if (node == NULL)
		return NULL;

	node->date_time_ext_value = value;
	node->length = sizeof(int64_t);
	return node;
}

/**
 * Returns the value of a KMIP node of type date and time extended
 *
 * @param node              the KMIP node
 *
 * @returns the value of the node, or 0 if the node is not of type date and time
 * extended
 */
int64_t kmip_node_get_date_time_ext(const struct kmip_node *node)
{
	if (node == NULL)
		return 0;

	if (node->type != KMIP_TYPE_DATE_TIME_EXTENDED)
		return 0;

	return node->date_time_ext_value;
}

/**
 * Clones (copies) a KMIP node with all its data and elements (in case of a
 * structure node).
 *
 * @param node              the KMIP node to clone
 *
 * @returns the cloned node, or NULL in case of an error
 */
struct kmip_node *kmip_node_clone(const struct kmip_node *node)
{
	struct kmip_node *clone, *element, *cloned_element;
	int rc;

	clone = kmip_node_new(node->tag, node->name, node->type);
	if (clone == NULL)
		return NULL;

	switch (clone->type) {
	case KMIP_TYPE_STRUCTURE:
		element = node->structure_value;
		while (element != NULL) {
			cloned_element = kmip_node_clone(element);
			if (cloned_element == NULL)
				goto error;
			rc = kmip_node_add_structure_element(clone,
							     cloned_element);
			kmip_node_free(cloned_element);
			if (rc != 0)
				goto error;
			element = element->next;
		}
		break;
	case KMIP_TYPE_INTEGER:
		clone->integer_value = node->integer_value;
		break;
	case KMIP_TYPE_LONG_INTEGER:
		clone->long_value = node->long_value;
		break;
	case KMIP_TYPE_BIG_INTEGER:
		clone->big_integer_value = BN_dup(node->big_integer_value);
		if (clone->big_integer_value == NULL)
			goto error;
		break;
	case KMIP_TYPE_ENUMERATION:
		clone->enumeration_value = node->enumeration_value;
		break;
	case KMIP_TYPE_BOOLEAN:
		clone->boolean_value = node->boolean_value;
		break;
	case KMIP_TYPE_TEXT_STRING:
		if (node->text_value != NULL) {
			clone->text_value = strdup(node->text_value);
			if (node->text_value == NULL)
				goto error;
			clone->length = strlen(clone->text_value);
		}
		break;
	case KMIP_TYPE_BYTE_STRING:
		if (node->bytes_value != NULL && node->length > 0) {
			clone->bytes_value = malloc(node->length);
			if (clone->bytes_value == NULL)
				goto error;
			memcpy(clone->bytes_value, node->bytes_value,
			       node->length);
			clone->length = node->length;
		}
		break;
	case KMIP_TYPE_DATE_TIME:
		clone->date_time_value = node->date_time_value;
		break;
	case KMIP_TYPE_INTERVAL:
		clone->interval_value = node->interval_value;
		break;
	case KMIP_TYPE_DATE_TIME_EXTENDED:
		clone->date_time_ext_value = node->date_time_ext_value;
		break;
	default:
		goto error;
	}

	return clone;

error:
	kmip_node_free(clone);
	return NULL;
}

/**
 * Increments the reference count of a KMIP node
 *
 * @param node              the node to increase the reference count for
 */
void kmip_node_upref(struct kmip_node *node)
{
	if (node == NULL)
		return;

	__sync_add_and_fetch((unsigned long *)&node->ref_count, 1);
}

/**
 * Free a KMIP node, including its value (structure elements, etc)
 *
 * @param node              the node to free
 */
void kmip_node_free(struct kmip_node *node)
{
	struct kmip_node *element, *next;
	unsigned long ref_count = 0;

	if (node == NULL)
		return;

	if (node->ref_count > 0)
		ref_count = __sync_sub_and_fetch(
					(unsigned long *)&node->ref_count, 1);
	if (ref_count > 0)
		return;

	switch (node->type) {
	case KMIP_TYPE_STRUCTURE:
		element = node->structure_value;
		while (element != NULL) {
			next = element->next;

			/*
			 * Unchain the element from the parent and next element,
			 * even if the element itself might not be freed (due
			 * to reference count). But the parent is freed, and
			 * thus the chain of elements is not longer existent.
			 */
			element->parent = NULL;
			element->next = NULL;

			kmip_node_free(element);

			element = next;
		}
		break;
	case KMIP_TYPE_BIG_INTEGER:
		BN_free(node->big_integer_value);
		break;
	case KMIP_TYPE_TEXT_STRING:
		free(node->text_value);
		break;
	case KMIP_TYPE_BYTE_STRING:
		free(node->bytes_value);
		break;
	default:
		break;
	}

	free(node->name);
	free(node);
}

static struct kmip_version default_protocol_version = {
	.major = KMIP_DEFAULT_PROTOCOL_VERSION_MAJOR,
	.minor = KMIP_DEFAULT_PROTOCOL_VERSION_MINOR
};

/**
 * Sets the default KMIP protocol version
 *
 * @param version           the version to set
 */
void kmip_set_default_protocol_version(const struct kmip_version *version)
{
	if (version == NULL)
		return;

	default_protocol_version.major = version->major;
	default_protocol_version.minor = version->minor;
}

/**
 * Sets the default KMIP protocol version
 *
 * @returns the default KMIP protocol version
 */
const struct kmip_version *kmip_get_default_protocol_version(void)
{
	return &default_protocol_version;
}

/**
 * Constructs a new connection to a KMIP server using the specified connection
 * configuration. The strings specified in the configuration are copied into the
 * newly allocated connection, they can be freed by the caller after the new
 * connection has been allocated. The reference count in  the PKEY specified
 * in the configuration is increased. The caller can free its PKEY as needed.
 *
 * @param config            the connection configuration
 * @param connection        On return: a newly allocated KMIP connection
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_connection_new(const struct kmip_conn_config *config,
			struct kmip_connection **connection,
			bool debug)
{
	struct kmip_connection *conn = NULL;
	int rc;

	if (config == NULL || connection == NULL)
		return -EINVAL;

	*connection = NULL;

	switch (config->encoding) {
	case KMIP_ENCODING_TTLV:
		/* TTLV can be used with both, plain-TLS and HTTPS */
		switch (config->transport) {
		case KMIP_TRANSPORT_PLAIN_TLS:
#ifdef HAVE_LIBCURL
		case KMIP_TRANSPORT_HTTPS:
#endif
			break;
		default:
			kmip_debug(debug, "Invalid transport: %d",
				   config->transport);
			return -EINVAL;
		}
		break;
#ifdef HAVE_LIBCURL
#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
#endif
#if defined HAVE_LIBJSONC || defined HAVE_LIBXML2
		/* JSON/XML can only be used with HTTPS */
		switch (config->transport) {
		case KMIP_TRANSPORT_PLAIN_TLS:
			kmip_debug(debug, "JSON/XML encode can only be used "
				   "with HTTPS transport");
			return -EINVAL;
#ifdef HAVE_LIBCURL
		case KMIP_TRANSPORT_HTTPS:
#endif
			break;
		default:
			kmip_debug(debug, "Invalid transport: %d",
				   config->transport);
			return -EINVAL;
		}
		break;
#endif
#endif
	default:
		kmip_debug(debug, "Invalid encoding: %d", config->encoding);
		return -EINVAL;
	}

	if (config->server == NULL) {
		kmip_debug(debug, "KMIP Server must be specified");
		return -EINVAL;
	}
	if (config->tls_client_key == NULL) {
		kmip_debug(debug, "Client key must be specified");
		return -EINVAL;
	}
	if (config->tls_client_cert == NULL) {
		kmip_debug(debug, "Client certificate must be specified");
		return -EINVAL;
	}

	conn = calloc(1, sizeof(struct kmip_connection));
	if (conn == NULL) {
		kmip_debug(debug, "calloc failed");
		return -ENOMEM;
	}

	conn->config.encoding = config->encoding;
	conn->config.transport = config->transport;
	kmip_debug(debug, "encoding: %d", conn->config.encoding);
	kmip_debug(debug, "transport: %d", conn->config.transport);

	conn->config.server = strdup(config->server);
	if (conn->config.server == NULL) {
		kmip_debug(debug, "strdup failed");
		rc = -ENOMEM;
		goto out;
	}
	kmip_debug(debug, "server: '%s'", conn->config.server);

	conn->config.tls_client_key = config->tls_client_key;
	if (EVP_PKEY_up_ref(conn->config.tls_client_key) != 1) {
		kmip_debug(debug, "EVP_PKEY_up_ref failed");
		rc = -EIO;
		goto out;
	}
	kmip_debug(debug, "client key: %p", conn->config.tls_client_key);

	conn->config.tls_client_cert = strdup(config->tls_client_cert);
	if (conn->config.tls_client_cert == NULL) {
		kmip_debug(debug, "strdup failed");
		rc = -ENOMEM;
		goto out;
	}
	kmip_debug(debug, "client cert: '%s'", conn->config.tls_client_cert);

	if (config->tls_ca != NULL) {
		conn->config.tls_ca = strdup(config->tls_ca);
		if (conn->config.tls_ca == NULL) {
			kmip_debug(debug, "strdup failed");
			rc = -ENOMEM;
			goto out;
		}
		kmip_debug(debug, "CA: '%s'", conn->config.tls_ca);
	}

	if (config->tls_issuer_cert != NULL) {
		conn->config.tls_issuer_cert = strdup(config->tls_issuer_cert);
		if (conn->config.tls_issuer_cert == NULL) {
			kmip_debug(debug, "strdup failed");
			rc = -ENOMEM;
			goto out;
		}
		kmip_debug(debug, "issuer cert: '%s'",
			   conn->config.tls_issuer_cert);
	}

	if (config->tls_pinned_pubkey != NULL) {
		conn->config.tls_pinned_pubkey =
					strdup(config->tls_pinned_pubkey);
		if (conn->config.tls_pinned_pubkey == NULL) {
			kmip_debug(debug, "strdup failed");
			rc = -ENOMEM;
			goto out;
		}
		kmip_debug(debug, "pinned pubkey: '%s'",
			   conn->config.tls_pinned_pubkey);
	}

	if (config->tls_server_cert != NULL) {
		conn->config.tls_server_cert = strdup(config->tls_server_cert);
		if (conn->config.tls_server_cert == NULL) {
			kmip_debug(debug, "strdup failed");
			rc = -ENOMEM;
			goto out;
		}
		kmip_debug(debug, "server cert: '%s'",
			   conn->config.tls_server_cert);
	}

	conn->config.tls_verify_peer = config->tls_verify_peer;
	conn->config.tls_verify_host = config->tls_verify_host;
	kmip_debug(debug, "verify peer: %d", conn->config.tls_verify_peer);
	kmip_debug(debug, "verify host: %d", conn->config.tls_verify_host);

	if (config->tls_cipher_list != NULL) {
		conn->config.tls_cipher_list = strdup(config->tls_cipher_list);
		if (conn->config.tls_cipher_list == NULL) {
			kmip_debug(debug, "strdup failed");
			rc = -ENOMEM;
			goto out;
		}
		kmip_debug(debug, "TLS cipher list: '%s'",
			   conn->config.tls_cipher_list);
	}

	if (config->tls13_cipher_list != NULL) {
		conn->config.tls13_cipher_list =
					strdup(config->tls13_cipher_list);
		if (conn->config.tls13_cipher_list == NULL) {
			kmip_debug(debug, "strdup failed");
			rc = -ENOMEM;
			goto out;
		}
		kmip_debug(debug, "TLSv1.3 cipher list: '%s'",
			   conn->config.tls13_cipher_list);
	}

	switch (conn->config.transport) {
	case KMIP_TRANSPORT_PLAIN_TLS:
		rc = kmip_connection_tls_init(conn, debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_connection_tls_init failed");
			goto out;
		}
		break;
#ifdef HAVE_LIBCURL
	case KMIP_TRANSPORT_HTTPS:
		rc = kmip_connection_https_init(conn, debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_connection_https_init failed");
			goto out;
		}
		break;
#endif
	default:
		kmip_debug(debug, "Invalid transport: %d",
			   conn->config.transport);
		rc =  -EINVAL;
		goto out;
	}

	*connection = conn;
	rc = 0;

out:
	if (rc != 0)
		kmip_connection_free(conn);

	return rc;
}

/**
 * Perform a request over the KMIP connection
 *
 * @param connection        the KMIP connection
 * @param request           the request to send
 * @param response          On return: the received response. Must be freed by
 *                          the caller.
 *
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_connection_perform(struct kmip_connection *connection,
			    struct kmip_node *request,
			    struct kmip_node **response,
			    bool debug)
{
	int rc;

	if (connection == NULL || request == NULL || response == NULL)
		return -EINVAL;

	kmip_debug(debug, "KMIP Request:");
	kmip_node_dump(request, debug);

	switch (connection->config.transport) {
	case KMIP_TRANSPORT_PLAIN_TLS:
		rc = kmip_connection_tls_perform(connection, request,
						 response, debug);
		break;
#ifdef HAVE_LIBCURL
	case KMIP_TRANSPORT_HTTPS:
		rc = kmip_connection_https_perform(connection, request,
						   response, debug);
		break;
#endif
	default:
		return -EINVAL;
	}

	if (rc == 0 && *response != NULL) {
		kmip_debug(debug, "KMIP Response:");
		kmip_node_dump(*response, debug);
	}

	return rc;
}

/**
 * Terminates and frees a KMIP connection.
 *
 * @param connection        the KMIP connection to free
 */
void kmip_connection_free(struct kmip_connection *connection)
{
	if (connection == NULL)
		return;

	switch (connection->config.transport) {
	case KMIP_TRANSPORT_PLAIN_TLS:
		kmip_connection_tls_term(connection);
		break;
#ifdef HAVE_LIBCURL
	case KMIP_TRANSPORT_HTTPS:
		kmip_connection_https_term(connection);
		break;
#endif
	default:
		break;
	}

	free((void *)connection->config.server);
	EVP_PKEY_free(connection->config.tls_client_key);
	free((void *)connection->config.tls_client_cert);
	if (connection->config.tls_ca != NULL)
		free((void *)connection->config.tls_ca);
	if (connection->config.tls_issuer_cert != NULL)
		free((void *)connection->config.tls_issuer_cert);
	if (connection->config.tls_pinned_pubkey != NULL)
		free((void *)connection->config.tls_pinned_pubkey);
	if (connection->config.tls_server_cert != NULL)
		free((void *)connection->config.tls_server_cert);
	if (connection->config.tls_cipher_list != NULL)
		free((void *)connection->config.tls_cipher_list);
	if (connection->config.tls13_cipher_list != NULL)
		free((void *)connection->config.tls13_cipher_list);

	free(connection);
}

/**
 * Retrieves the serevr's certificate, public key and certificate chain
 *
 * @param server            the KMIP server.
 *                          For Plain-TLS transport, only the hostname and
 *                          optional port number.
 *                          For HTTPS transport, an URL in the form
 *                          'https://hostname[:port]/uri'
 * @param transport         the transport mode
 * @param ca                Optional: File name of the CA bundle PEM file, or a
 *                          name of a directory the multiple CA certificates.
 *                          If this is NULL, then the default system path for
 *                          CA certificates is used.
 * @param client_key        the client key as an OpenSSL PKEY object.
 * @param client_cert       File name of the client certificate PEM file
 * @param server_cert_pem   File name of a PEM file into which the server
 *                          certificate is written. If NULL then ignored.
 * @param server_pubkey_pem File name of a PEM file into which the server
 *                          public key is written. If NULL then ignored.
 * @param cert_chain_pem    File name of a PEM file into which the certificate
 *                          chain (excluding the server certificate) is written.
 *                          If NULL then ignored.
 * @param verified          On return: If the server 's certificate has been
 *                          verified using the CA specification (if ca = NULL:
 *                          default system CAs, otherwise path or file to CAs).
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_connection_get_server_cert(const char *server,
				    enum kmip_transport transport,
				    const char *ca,
				    EVP_PKEY *client_key,
				    const char *client_cert,
				    const char *server_cert_pem,
				    const char *server_pubkey_pem,
				    const char *cert_chain_pem,
				    bool *verified,
				    bool debug)
{
	struct kmip_conn_config config = { 0 };
	struct kmip_connection *conn = NULL;
	int rc, numcerts, i;
	char *hostname = NULL;
#ifdef HAVE_LIBCURL
    int port_found = 0;
	char *tok, *tok2;
#endif
	STACK_OF(X509) *chain;
	bool do_verify = true;
	FILE *fp = NULL;
	X509 *cert;

	if (server == NULL || client_key == NULL || client_cert == NULL)
		return -EINVAL;

	config.encoding = KMIP_ENCODING_TTLV;
	config.transport = KMIP_TRANSPORT_PLAIN_TLS;
	config.tls_ca = ca;
	config.tls_client_key = client_key;
	config.tls_client_cert = client_cert;
	config.tls_verify_host = false;
	config.tls_verify_peer = false;
	config.tls_cipher_list = NULL;
	config.tls13_cipher_list = NULL;

#ifdef HAVE_LIBCURL
	if (transport == KMIP_TRANSPORT_HTTPS) {
		if (strncmp(server, "https://", 8) != 0) {
			kmip_debug(debug, "Server must start with 'https://'");
			return -EINVAL;
		}
		server += 8;

		/* Find port (if any) and beginning of uri */
		if (*server == '[') {
			/* IPv6 address enclosed in square brackets */
			tok = strchr(server, ']');
			if (tok == NULL) {
				kmip_debug(debug, "malformed IPv6 address");
				return -EINVAL;
			}
			tok++;
			if (*tok == ':') {
				port_found = 1;
				tok2 = strchr(tok, '/');
				if (tok2 == NULL)
					tok2 = tok + strlen(tok);
			} else {
				tok2 = strchr(tok, '/');
				if (tok2 == NULL)
					tok2 = tok + strlen(tok);
			}
		} else {
			/* hostname or IPv4 address */
			tok = strchr(server, ':');
			if (tok != NULL) {
				port_found = 1;
				tok2 = strchr(tok, '/');
				if (tok2 == NULL)
					tok2 = tok + strlen(tok);
			} else {
				tok2 = strchr(server, '/');
				if (tok2 == NULL)
					tok2 = (char *)server + strlen(server);
			}
		}

		hostname = calloc(1, tok2 - server + (!port_found ? 5 : 1));
		if (hostname == NULL) {
			kmip_debug(debug, "calloc failed");
			return -ENOMEM;
		}
		strncpy(hostname, server, tok2 - server);
		if (!port_found) {
			strcat(hostname, ":");
			strcat(hostname, KMIP_DEFAULT_HTTPS_PORT);
		}

		config.server = hostname;
	} else {
#else
	if (transport == KMIP_TRANSPORT_PLAIN_TLS) {
#endif
		config.server = server;
	}

retry:
	config.tls_verify_peer = do_verify;
	rc = kmip_connection_new(&config, &conn, debug);
	if (rc != 0) {
		kmip_debug(debug, "kmip_connection_new failed (do_verify: %d)",
			   do_verify);

		if (do_verify) {
			/*
			 * If peer verification failed (e.g. due to a self
			 * signed server certificate), try again without peer
			 * verification.
			 */
			do_verify = false;
			goto retry;
		}
		goto out;
	}

	if (verified != NULL)
		*verified = do_verify;

	chain = SSL_get_peer_cert_chain(conn->plain_tls.ssl);
	if (chain == NULL) {
		kmip_debug(debug, "SSL_get_peer_cert_chain failed");
		rc = -EIO;
		goto out;
	}

	numcerts = sk_X509_num(chain);
	for (i = 0; i < numcerts; i++) {
		cert = sk_X509_value(chain, i);
		if (cert == NULL)
			break;

		if (debug) {
			kmip_debug(debug, "%d. Certificate:", i);
			X509_print_ex_fp(stderr, cert, XN_FLAG_COMPAT,
					 X509_FLAG_COMPAT);
		}

		if (i == 0 && server_cert_pem != NULL) {
			fp = fopen(server_cert_pem, "w");
			if (fp == NULL) {
				rc = -errno;
				kmip_debug(debug, "Failed to open %s for write",
					   server_cert_pem, strerror(-rc));
				goto out;
			}

			if (PEM_write_X509(fp, cert) != 1) {
				kmip_debug(debug, "PEM_write_X509 failed to "
					   "write to %s", server_cert_pem);
				rc = -EIO;
				goto out;
			}
			fclose(fp);
			fp = NULL;

			if (server_pubkey_pem != NULL) {
				fp = fopen(server_pubkey_pem, "w");
				if (fp == NULL) {
					rc = -errno;
					kmip_debug(debug, "Failed to open %s "
						   "for write",
						   server_pubkey_pem,
						   strerror(-rc));
					goto out;
				}

				if (PEM_write_PUBKEY(fp, X509_get0_pubkey(cert))
									!= 1) {
					kmip_debug(debug, "PEM_write_PUBKEY "
						   "failed to write to %s",
						   server_pubkey_pem);
					rc = -EIO;
					goto out;
				}
				fclose(fp);
				fp = NULL;
			}
			continue;
		}

		if (i > 0 && cert_chain_pem != NULL) {
			if (fp == NULL)
				fp = fopen(cert_chain_pem, "w");
			if (fp == NULL) {
				rc = -errno;
				kmip_debug(debug, "Failed to open %s for write",
					   cert_chain_pem, strerror(-rc));
				goto out;
			}

			if (PEM_write_X509(fp, cert) != 1) {
				kmip_debug(debug, "PEM_write_X509 failed to "
					   "write to %s", cert_chain_pem);
				rc = -EIO;
				goto out;
			}
		}
	}

	rc = 0;

out:
	if (fp != NULL)
		fclose(fp);
	if (conn != NULL)
		kmip_connection_free(conn);
	if (hostname != NULL)
		free(hostname);

	return rc;
}

/**
 * Library constructor
 */
void __attribute__ ((constructor)) kmip_init(void)
{
#ifdef HAVE_LIBCURL
	CURLsslset rc;

	/*
	 * Ensure that curl uses OpenSSL as SSL backend. If curl has already
	 * been itialized by the calling application, the backend can't be
	 * changed anymore, but we continue anyway. However, it will later be
	 * checked if curl uses the OpenSSL backend, and a HTTPS connection
	 * will fail if it is not using the OpenSSL backend.
	 */
	rc = curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL);
	if (rc != CURLSSLSET_OK && rc != CURLSSLSET_TOO_LATE)
		errx(EXIT_FAILURE, "libkmipclient: libcurl was not built with "
		     "the OpenSSL backend");

	curl_global_init(CURL_GLOBAL_ALL);
#endif
}

/**
 * Library destructor
 */
void __attribute__ ((destructor)) kmip_exit(void)
{
#ifdef HAVE_LIBCURL
	curl_global_cleanup();
#endif
}
