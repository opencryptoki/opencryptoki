/*
 * COPYRIGHT (c) International Business Machines Corp. 2021-2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <errno.h>
#include <string.h>

#ifdef HAVE_LIBCURL
#ifdef HAVE_LIBJSONC

#include "kmip.h"
#include "names.h"
#include "utils.h"

#define KMIP_JSON_TAG		"tag"
#define KMIP_JSON_NAME		"name"
#define KMIP_JSON_TYPE		"type"
#define KMIP_JSON_VALUE		"value"

/**
 * Decode a KMIP node from the data in a JSON object using the JSON encoding.
 *
 * @param obj               the JSON object to decode
 * @param parent            the parent node or NULL if no parent exists.
 * @param node              On return: the decoded node. The newly allocated
 *                          node has a reference count of 1.
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_decode_json(const json_object *obj, struct kmip_node *parent,
		     struct kmip_node **node, bool debug)
{
	json_object *tag_obj, *type_obj, *value_obj, *name_obj;
	enum kmip_tag tag, v1_attr_tag = 0;
	enum json_type value_type;
	struct kmip_node *n, *e;
	const char *str;
	int rc, num, i;
	int64_t int64;

	if (obj == NULL || node == NULL)
		return -EINVAL;

	if (!json_object_is_type(obj, json_type_object)) {
		kmip_debug(debug, "Object is not a JSON object");
		return -EINVAL;
	}

	n = calloc(1, sizeof(struct kmip_node));
	if (n == NULL) {
		kmip_debug(debug, "calloc failed");
		return -ENOMEM;
	}
	n->ref_count = 1;

	tag_obj = json_object_object_get(obj, KMIP_JSON_TAG);
	if (tag_obj == NULL ||
	    !json_object_is_type(tag_obj, json_type_string)) {
		kmip_debug(debug, "Missing or invalid '%s' in JSON object",
			   KMIP_JSON_TAG);
		rc = -EBADMSG;
		goto out;
	}

	str = json_object_get_string(tag_obj);
	n->tag = kmip_tag_by_name_or_hex(str);
	if (n->tag == 0) {
		kmip_debug(debug, "Unknown 'tag' in JSON object: '%s'", str);
		rc = -EBADMSG;
		goto out;
	}

	name_obj = json_object_object_get(obj, KMIP_JSON_NAME);
	if (name_obj != NULL) {
		if (!json_object_is_type(name_obj, json_type_string)) {
			kmip_debug(debug, "Invalid '%s' in JSON object",
				   KMIP_JSON_NAME);
			rc = -EBADMSG;
			goto out;
		}
		n->name = strdup(json_object_get_string(tag_obj));
	}

	type_obj = json_object_object_get(obj, KMIP_JSON_TYPE);
	if (type_obj == NULL) {
		n->type = KMIP_TYPE_STRUCTURE;
	} else {
		if (!json_object_is_type(type_obj, json_type_string)) {
			kmip_debug(debug,
				   "Missing or invalid '%s' in JSON object",
				   KMIP_JSON_TYPE);
			rc = -EBADMSG;
			goto out;
		}

		str = json_object_get_string(type_obj);
		n->type = kmip_type_by_name_or_hex(str);
		if (n->type == 0) {
			kmip_debug(debug, "Unknown 'type' in JSON object: '%s'",
				   str);
			rc = -EBADMSG;
			goto out;
		}
	}

	value_obj = json_object_object_get(obj, KMIP_JSON_VALUE);
	if (value_obj == NULL) {
		kmip_debug(debug, "Missing '%s' in JSON object",
			   KMIP_JSON_VALUE);
		rc = -EBADMSG;
		goto out;
	}
	value_type = json_object_get_type(value_obj);

	/*
	 * KMIP v1.x attribute values may be Enumerations or Integer Masks.
	 * To correctly decode them, we need to know the tag. This is contained
	 * in a Attribute Name node, which is an element of our parent node.
	 */
	if (n->tag == KMIP_TAG_ATTRIBUTE_VALUE)
		v1_attr_tag = kmip_find_v1_attribute_name_tag(parent);
	tag = (v1_attr_tag != 0 ? v1_attr_tag : n->tag);

	kmip_debug(debug, "tag: 0x%x type: 0x%x value_type: %d,", n->tag,
		   n->type, value_type);

	switch (n->type) {
	case KMIP_TYPE_STRUCTURE:
		switch (value_type) {
		case json_type_null:
			break;
		case json_type_array:
			num = json_object_array_length(value_obj);
			for (i = 0; i < num; i++) {
				rc = kmip_decode_json(
					json_object_array_get_idx(value_obj, i),
					n, &e, debug);
				if (rc != 0) {
					kmip_debug(debug, "Failed to parse "
						   "array element %d", i);
					goto out;
				}
				rc = kmip_node_add_structure_element(n, e);
				kmip_node_free(e);
				if (rc != 0) {
					kmip_debug(debug,
						"kmip_node_structure_add_element "
						"failed: rc: %d", rc);
					goto out;
				}
			}
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	case KMIP_TYPE_INTEGER:
	case KMIP_TYPE_LONG_INTEGER:
		switch (value_type) {
		case json_type_int:
		case json_type_double:
			int64 = json_object_get_int64(value_obj);
			break;
		case json_type_string:
			str = json_object_get_string(value_obj);
			if (n->type == KMIP_TYPE_INTEGER &&
			    kmip_is_tag_mask(tag)) {
				rc = kmip_parse_mask(tag, str, '|', &int64);
				if (rc != 0) {
					kmip_debug(debug, "Failed to parse "
						   "mask string '%s'", str);
					goto out;
				}
			} else {
				rc = kmip_parse_hex_int(str, &int64);
				if (rc != 0) {
					kmip_debug(debug, "Failed to parse "
						   "hex string '%s'", str);
					goto out;
				}
			}
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		if (n->type == KMIP_TYPE_INTEGER)
			n->integer_value = int64;
		else
			n->long_value = int64;
		break;

	case KMIP_TYPE_INTERVAL:
		switch (value_type) {
		case json_type_int:
		case json_type_double:
			n->interval_value = json_object_get_int64(value_obj);
			break;
		case json_type_string:
			str = json_object_get_string(value_obj);
			rc = kmip_parse_hex_int(str, &int64);
			if (rc != 0) {
				kmip_debug(debug, "Failed to parse "
					   "hex string '%s'", str);
				goto out;
			}
			n->interval_value = int64;
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;


	case KMIP_TYPE_BIG_INTEGER:
		switch (value_type) {
		case json_type_int:
		case json_type_double:
			int64 = htobe64(json_object_get_int64(value_obj));
			rc = kmip_decode_bignum((const unsigned char *)&int64,
						 sizeof(int64),
						 &n->big_integer_value);
			if (rc != 0) {
				kmip_debug(debug, "kmip_decode_bignum failed");
				goto out;
			}
			break;
		case json_type_string:
			str = json_object_get_string(value_obj);
			rc = kmip_parse_bignum(str, true,
					       &n->big_integer_value);
			if (rc != 0) {
				kmip_debug(debug,
					   "Failed to parse bignum string '%s'",
					   str);
				goto out;
			}
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	case KMIP_TYPE_ENUMERATION:
		switch (value_type) {
		case json_type_int:
		case json_type_double:
			n->enumeration_value = json_object_get_int64(value_obj);
			break;
		case json_type_string:
			str = json_object_get_string(value_obj);
			rc = kmip_enum_value_by_tag_name_or_hex(tag, str,
							&n->enumeration_value);
			if (rc != 0) {
				kmip_debug(debug,
					   "Failed to parse enumeration '%s'",
					   str);
				goto out;
			}
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	case KMIP_TYPE_BOOLEAN:
		switch (value_type) {
		case json_type_boolean:
			n->boolean_value = json_object_get_boolean(value_obj);
			break;
		case json_type_string:
			str = json_object_get_string(value_obj);
			rc = kmip_parse_hex_int(str, &int64);
			if (rc != 0) {
				kmip_debug(debug,
					   "Failed to parse hex string '%s'",
					   str);
				goto out;
			}
			n->boolean_value = (int64 != 0);
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	case KMIP_TYPE_TEXT_STRING:
		switch (value_type) {
		case json_type_string:
			n->text_value = strdup(
					json_object_get_string(value_obj));
			if (n->text_value == NULL) {
				rc = -ENOMEM;
				goto out;
			}
			n->length = strlen(n->text_value);
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	case KMIP_TYPE_BYTE_STRING:
		switch (value_type) {
		case json_type_string:
			str = json_object_get_string(value_obj);
			rc = kmip_parse_hex(str, false, &n->bytes_value,
					    &n->length);
			if (rc != 0) {
				kmip_debug(debug,
					   "Failed to parse hex string '%s'",
					   str);
				goto out;
			}
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	case KMIP_TYPE_DATE_TIME:
		switch (value_type) {
		case json_type_int:
		case json_type_double:
			n->date_time_value = json_object_get_int64(value_obj);
			break;
		case json_type_string:
			str = json_object_get_string(value_obj);
			rc = kmip_parse_timestamp(str, &n->date_time_value);
			if (rc != 0) {
				kmip_debug(debug,
					   "Failed to parse time stamp '%s'",
					   str);
				goto out;
			}
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	case KMIP_TYPE_DATE_TIME_EXTENDED:
		switch (value_type) {
		case json_type_int:
		case json_type_double:
			n->date_time_ext_value =
					json_object_get_int64(value_obj);
			break;
		case json_type_string:
			str = json_object_get_string(value_obj);
			rc = kmip_parse_hex_int(str, &int64);
			if (rc != 0) {
				kmip_debug(debug,
					   "Failed to parse hex string '%s'",
					   str);
				goto out;
			}
			n->date_time_ext_value = int64;
			break;
		default:
			kmip_debug(debug, "Invalid JSON type %d for node type "
				   "0x%x", value_type, n->type);
			rc = -EBADMSG;
			goto out;
		}
		break;

	default:
		kmip_debug(debug, "unknown type: 0x%x", n->type);
		rc = -EBADMSG;
		goto out;
	}

	*node = n;
	rc = 0;

out:
	if (rc != 0)
		kmip_node_free(n);
	return rc;
}

/**
 * Encode a KMIP node into a JSON object using the JSON encoding.
 *
 * @param node              the node to encode
 * @param obj               On return: the JSON object
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_encode_json(const struct kmip_node *node, json_object **obj,
		     bool debug)
{
	json_object *ret_obj = NULL, *memb_obj, *elem_obj;
	enum kmip_tag tag, v1_attr_tag = 0;
	struct kmip_node *element;
	char outstr[200] = { 0 };
	const char *str;
	int64_t int64;
	struct tm *tm;
	char *tmp;
	char *s;
	int rc;

	if (node == NULL || obj == NULL)
		return -EINVAL;

	kmip_debug(debug, "tag: 0x%x type: 0x%x", node->tag, node->type);

	ret_obj = json_object_new_object();
	if (ret_obj == NULL) {
		kmip_debug(debug, "Failed to allocate a JSON object");
		return -ENOMEM;
	}

	memb_obj = json_object_new_string(
				kmip_tag_name_or_hex_by_tag(node->tag,
							    outstr));
	if (memb_obj == NULL) {
		kmip_debug(debug, "Failed to build JSON object for tag");
		rc = -ENOMEM;
		goto out;
	}
	rc = json_object_object_add(ret_obj, KMIP_JSON_TAG, memb_obj);
	if (rc != 0) {
		kmip_debug(debug, "Failed to add JSON object for tag");
		rc = -EIO;
		goto out;
	}

	if (node->name != NULL) {
		memb_obj = json_object_new_string(node->name);
		if (memb_obj == NULL) {
			kmip_debug(debug,
				   "Failed to build JSON object for name");
			rc = -ENOMEM;
			goto out;
		}
		rc = json_object_object_add(ret_obj, KMIP_JSON_NAME, memb_obj);
		if (rc != 0) {
			kmip_debug(debug, "Failed to add JSON object for name");
			rc = -EIO;
			goto out;
		}
	}

	if (node->type != KMIP_TYPE_STRUCTURE) {
		str = kmip_type_name_by_type(node->type);
		if (str == NULL) {
			kmip_debug(debug, "unknown type 0x%x", node->type);
			rc = -EINVAL;
			goto out;
		}
		memb_obj = json_object_new_string(str);
		if (memb_obj == NULL) {
			kmip_debug(debug,
				   "Failed to build JSON object for type");
			rc = -ENOMEM;
			goto out;
		}
		rc = json_object_object_add(ret_obj, KMIP_JSON_TYPE, memb_obj);
		if (rc != 0) {
			kmip_debug(debug, "Failed to add JSON object for type");
			rc = -EIO;
			goto out;
		}
	}

	/*
	 * KMIP v1.x attribute values may be Enumerations or Integer Masks.
	 * To correctly encode them, we need to know the tag. This is contained
	 * in a Attribute Name node, which is an element of our parent node.
	 */
	if (node->tag == KMIP_TAG_ATTRIBUTE_VALUE)
		v1_attr_tag = kmip_find_v1_attribute_name_tag(node->parent);
	tag = (v1_attr_tag != 0 ? v1_attr_tag : node->tag);

	switch (node->type) {
	case KMIP_TYPE_STRUCTURE:
		memb_obj = json_object_new_array();
		if (memb_obj == NULL) {
			kmip_debug(debug,
				"Failed to build JSON object for value array");
			rc = -ENOMEM;
			goto out;
		}
		element = node->structure_value;
		while (element != NULL) {
			rc = kmip_encode_json(element, &elem_obj, debug);
			if (rc != 0) {
				kmip_debug(debug, "kmip_encode_json failed");
				goto out;
			}
			rc = json_object_array_add(memb_obj, elem_obj);
			if (rc != 0) {
				kmip_debug(debug,
					   "json_object_array_add failed");
				rc = EIO;
				goto out;
			}
			element = element->next;
		}
		break;

	case KMIP_TYPE_INTEGER:
		if (kmip_is_tag_mask(tag) && node->integer_value != 0) {
			rc = kmip_format_mask(tag, node->integer_value,
					      '|', &tmp);
			if (rc != 0) {
				kmip_debug(debug, "kmip_format_mask failed");
				goto out;
			}
			memb_obj = json_object_new_string(tmp);
			free(tmp);
		} else {
			memb_obj = json_object_new_int(node->integer_value);
		}
		break;

	case KMIP_TYPE_INTERVAL:
		memb_obj = json_object_new_int(node->interval_value);
		break;

	case KMIP_TYPE_LONG_INTEGER:
	case KMIP_TYPE_DATE_TIME_EXTENDED:
		if (node->type == KMIP_TYPE_LONG_INTEGER)
			int64 = node->long_value;
		else
			int64 = node->date_time_ext_value;
		/* any values >= 2^52 must be represented as hex strings */
		if (int64 < 4503599627370496 &&
		    int64 > -4503599627370496) {
			memb_obj = json_object_new_int64(int64);
		} else {
			rc = kmip_format_hex((const unsigned char *)&int64,
					     sizeof(int64), true, &tmp);
			if (rc != 0) {
				kmip_debug(debug, "kmip_format_hex failed");
				goto out;
			}
			memb_obj = json_object_new_string(tmp);
			free(tmp);
		}
		break;

	case KMIP_TYPE_BIG_INTEGER:
		rc = kmip_format_bignum(node->big_integer_value, true, &s);
		if (rc != 0) {
			kmip_debug(debug, "kmip_format_bignum failed");
			goto out;
		}
		memb_obj = json_object_new_string(s);
		free(s);
		break;

	case KMIP_TYPE_ENUMERATION:
		str = kmip_enum_name_by_tag_value(tag, node->enumeration_value);
		if (str != NULL)
			memb_obj = json_object_new_string(str);
		else
			memb_obj = json_object_new_int(node->enumeration_value);
		break;

	case KMIP_TYPE_BOOLEAN:
		memb_obj = json_object_new_boolean(node->boolean_value);
		break;

	case KMIP_TYPE_TEXT_STRING:
		memb_obj = json_object_new_string(node->text_value);
		break;

	case KMIP_TYPE_BYTE_STRING:
		rc = kmip_format_hex(node->bytes_value, node->length,
				     false, &s);
		if (rc != 0) {
			kmip_debug(debug, "kmip_format_hex_long failed");
			goto out;
		}
		memb_obj = json_object_new_string(s);
		free(s);
		break;

	case KMIP_TYPE_DATE_TIME:
		tm = gmtime((time_t *)&node->date_time_value);
		strftime(outstr, sizeof(outstr), KMIP_ISO8601_TIMESTAMP_UTC,
			 tm);
		memb_obj = json_object_new_string(outstr);
		break;

	default:
		kmip_debug(debug, "unknown type: 0x%x", node->type);
		rc = -EINVAL;
		goto out;
	}

	if (memb_obj == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = json_object_object_add(ret_obj, KMIP_JSON_VALUE, memb_obj);
	if (rc != 0) {
		kmip_debug(debug, "Failed to add JSON object for value");
		rc = -EIO;
		goto out;
	}

	rc = 0;
	*obj = ret_obj;

out:
	if (rc != 0)
		json_object_put(ret_obj);

	return rc;
}

#endif
#endif
