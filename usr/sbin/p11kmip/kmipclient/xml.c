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
#include <endian.h>
#include <string.h>

#ifdef HAVE_LIBCURL
#ifdef HAVE_LIBXML2

#include "kmip.h"
#include "names.h"
#include "utils.h"

#define KMIP_XML_TTLV		"TTLV"
#define KMIP_XML_TAG		"tag"
#define KMIP_XML_NAME		"name"
#define KMIP_XML_TYPE		"type"
#define KMIP_XML_VALUE		"value"

/**
 * Decode a KMIP node from the data in the XML node using the XML encoding.
 *
 * @param xml               the XML node to decode
 * @param parent            the parent node or NULL if no parent exists.
 * @param node              On return: the decoded node.The newly allocated
 *                          node has a reference count of 1.
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_decode_xml(const xmlNode *xml, struct kmip_node *parent,
		    struct kmip_node **node, bool debug)
{
	char *tag_attr = NULL, *name_attr = NULL, *type_attr = NULL;
	enum kmip_tag tag, v1_attr_tag = 0;
	char *tag_name, *value_attr = NULL;
	struct kmip_node *n = NULL, *e;
	uint64_t uint64;
	xmlNode *child;
	int64_t int64;
	int rc = 0, i;

	if (xml == NULL || node == NULL)
		return -EINVAL;

	if (xml->type != XML_ELEMENT_NODE) {
		kmip_debug(debug, "Invalid XML node type: %d", xml->type);
		return -EINVAL;
	}

	n = calloc(1, sizeof(struct kmip_node));
	if (n == NULL) {
		kmip_debug(debug, "calloc failed");
		return -ENOMEM;
	}
	n->ref_count = 1;

	if (strcmp((char *)xml->name, KMIP_XML_TTLV) == 0) {
		tag_attr = (char *)xmlGetProp(xml, (xmlChar *)KMIP_XML_TAG);
		if (tag_attr == NULL) {
			kmip_debug(debug, "Missing '%s' attribute in XML node",
				   KMIP_XML_TAG);
			rc = -EBADMSG;
			goto out;
		}
		tag_name = tag_attr;
	} else {
		tag_name = (char *)xml->name;
	}
	n->tag = kmip_tag_by_name_or_hex(tag_name);
	if (n->tag == 0) {
		kmip_debug(debug, "Unknown 'tag' in XML object: '%s'",
			   tag_name);
		rc = -EBADMSG;
		goto out;
	}

	name_attr = (char *)xmlGetProp(xml, (xmlChar *)KMIP_XML_NAME);
	if (name_attr != NULL)
		n->name = strdup(name_attr);

	type_attr = (char *)xmlGetProp(xml, (xmlChar *)KMIP_XML_TYPE);
	if (type_attr == NULL) {
		n->type = KMIP_TYPE_STRUCTURE;
	} else {
		n->type = kmip_type_by_name_or_hex(type_attr);
		if (n->type == 0) {
			kmip_debug(debug, "Unknown 'type' in XML object: '%s'",
				   type_attr);
			rc = -EBADMSG;
			goto out;
		}
	}

	value_attr = (char *)xmlGetProp(xml, (xmlChar *)KMIP_XML_VALUE);
	if (n->type != KMIP_TYPE_STRUCTURE && value_attr == NULL) {
		kmip_debug(debug, "Missing '%s' attribute in XML node",
			   KMIP_XML_VALUE);
		rc = -EBADMSG;
		goto out;
	}

	/*
	 * KMIP v1.x attribute values may be Enumerations or Integer Masks.
	 * To correctly decode them, we need to know the tag. This is contained
	 * in a Attribute Name node, which is an element of our parent node.
	 */
	if (n->tag == KMIP_TAG_ATTRIBUTE_VALUE)
		v1_attr_tag = kmip_find_v1_attribute_name_tag(parent);
	tag = (v1_attr_tag != 0 ? v1_attr_tag : n->tag);

	kmip_debug(debug, "tag: 0x%x type: 0x%x", n->tag, n->type);

	switch (n->type) {
	case KMIP_TYPE_STRUCTURE:
		for (child = xml->children, i = 0; child != NULL;
						child = child->next, i++) {
			if (child->type != XML_ELEMENT_NODE)
				continue;

			rc = kmip_decode_xml(child, n, &e, debug);
			if (rc != 0) {
				kmip_debug(debug, "Failed to parse child "
					   "element %d", i);
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

	case KMIP_TYPE_INTEGER:
	case KMIP_TYPE_LONG_INTEGER:
	case KMIP_TYPE_DATE_TIME_EXTENDED:
		if (n->type == KMIP_TYPE_INTEGER &&
		    kmip_is_tag_mask(tag)) {
			rc = kmip_parse_mask(tag, value_attr, ' ', &int64);
			if (rc != 0) {
				kmip_debug(debug, "Failed to parse "
					   "mask string '%s'", value_attr);
				goto out;
			}
		} else {
			rc = kmip_parse_decimal_int(value_attr, &int64);
			if (rc != 0) {
				kmip_debug(debug, "Failed to parse "
					   "decimal string '%s'", value_attr);
				goto out;
			}
		}

		switch (n->type) {
		case KMIP_TYPE_INTEGER:
			n->integer_value = int64;
			break;
		case KMIP_TYPE_LONG_INTEGER:
			n->long_value = int64;
			break;
		case KMIP_TYPE_DATE_TIME_EXTENDED:
			n->date_time_ext_value = int64;
			break;
		default:
			break;
		}
		break;

	case KMIP_TYPE_INTERVAL:
		rc = kmip_parse_decimal_uint(value_attr, &uint64);
		if (rc != 0) {
			kmip_debug(debug, "Failed to parse "
				   "decimal string '%s'", value_attr);
			goto out;
		}
		n->interval_value = uint64;
		break;

	case KMIP_TYPE_BIG_INTEGER:
		rc = kmip_parse_bignum(value_attr, false,
				       &n->big_integer_value);
		if (rc != 0) {
			kmip_debug(debug,
				   "Failed to parse bignum string '%s'",
				   value_attr);
			goto out;
		}
		break;

	case KMIP_TYPE_ENUMERATION:
		rc = kmip_enum_value_by_tag_name_or_hex(tag, value_attr,
							&n->enumeration_value);
		if (rc != 0) {
			kmip_debug(debug,
				   "Failed to parse enumeration '%s'",
				   value_attr);
			goto out;
		}
		break;

	case KMIP_TYPE_BOOLEAN:
		n->boolean_value = (strcmp(value_attr, "true") == 0 ||
				    strcmp(value_attr, "1") == 0);
		break;

	case KMIP_TYPE_TEXT_STRING:
		n->text_value = strdup(value_attr);
		if (n->text_value == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		n->length = strlen(n->text_value);
		break;

	case KMIP_TYPE_BYTE_STRING:
		rc = kmip_parse_hex(value_attr, false, &n->bytes_value,
				    &n->length);
		if (rc != 0) {
			kmip_debug(debug,
				   "Failed to parse hex string '%s'",
				   value_attr);
			goto out;
		}
		break;

	case KMIP_TYPE_DATE_TIME:
		rc = kmip_parse_timestamp(value_attr, &n->date_time_value);
		if (rc != 0) {
			kmip_debug(debug,
				   "Failed to parse time stamp '%s'",
				   value_attr);
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
	if (rc != 0 && n != NULL)
		kmip_node_free(n);
	if (tag_attr != NULL)
		xmlFree(tag_attr);
	if (name_attr != NULL)
		xmlFree(name_attr);
	if (type_attr != NULL)
		xmlFree(type_attr);
	if (value_attr != NULL)
		xmlFree(value_attr);

	return rc;
}

/**
 * Encode a KMIP node into an XML node using the XML encoding.
 *
 * @param node              the node to encode
 * @param xml               On return: the XML node
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_encode_xml(const struct kmip_node *node, xmlNode **xml, bool debug)
{
	enum kmip_tag tag, v1_attr_tag = 0;
	xmlNode *ret_xml = NULL, *elem_xml;
	struct kmip_node *element;
	const char *tag_name;
	char tmp_str[50];
	const char *str;
	struct tm *tm;
	xmlAttr *attr;
	char *tmp;
	int rc;

	if (node == NULL || xml == NULL)
		return -EINVAL;

	kmip_debug(debug, "tag: 0x%x type: 0x%x", node->tag, node->type);

	tag_name = kmip_tag_name_by_tag(node->tag);
	if (tag_name != NULL)
		ret_xml = xmlNewNode(NULL, (xmlChar *)tag_name);
	else
		ret_xml = xmlNewNode(NULL, (xmlChar *)KMIP_XML_TTLV);
	if (ret_xml == NULL) {
		kmip_debug(debug, "Failed to allocate a XML node");
		return -ENOMEM;
	}

	if (tag_name == NULL) {
		sprintf(tmp_str, "0x%06x", node->tag);
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_TAG,
				  (xmlChar *)tmp_str);
		if (attr == NULL) {
			kmip_debug(debug,
				   "Failed to add '%s' attribute to XML node",
				   KMIP_XML_TAG);
			rc = -ENOMEM;
			goto out;
		}

		if (node->name != NULL) {
			attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_NAME,
					  (xmlChar *)node->name);
			if (attr == NULL) {
				kmip_debug(debug, "Failed to add '%s' "
					   "attribute to XML node",
					   KMIP_XML_NAME);
				rc = -ENOMEM;
				goto out;
			}
		}
	}

	if (node->type != KMIP_TYPE_STRUCTURE) {
		str = kmip_type_name_by_type(node->type);
		if (str == NULL) {
			kmip_debug(debug, "unknown type 0x%x", node->type);
			rc = -EINVAL;
			goto out;
		}

		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_TYPE,
				  (xmlChar *)str);
		if (attr == NULL) {
			kmip_debug(debug,
				   "Failed to add '%s' attribute to XML node",
				   KMIP_XML_TYPE);
			rc = -ENOMEM;
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
		element = node->structure_value;
		while (element != NULL) {
			rc = kmip_encode_xml(element, &elem_xml, debug);
			if (rc != 0) {
				kmip_debug(debug, "kmip_encode_xml failed");
				goto out;
			}
			if (xmlAddChild(ret_xml, elem_xml) == NULL) {
				kmip_debug(debug, "xmlAddChild failed");
				rc = -EIO;
				goto out;
			}
			element = element->next;
		}
		attr = NULL;
		break;

	case KMIP_TYPE_INTEGER:
		if (kmip_is_tag_mask(tag) && node->integer_value != 0) {
			rc = kmip_format_mask(tag, node->integer_value,
					      ' ', &tmp);
			if (rc != 0) {
				kmip_debug(debug, "kmip_format_mask failed");
				goto out;
			}
			attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
					  (xmlChar *)tmp);
			free(tmp);
		} else {
			sprintf(tmp_str, "%d", node->integer_value);
			attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
					  (xmlChar *)tmp_str);
		}
		break;

	case KMIP_TYPE_INTERVAL:
		sprintf(tmp_str, "%u", node->interval_value);
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)tmp_str);
		break;

	case KMIP_TYPE_LONG_INTEGER:
		sprintf(tmp_str, "%ld", node->long_value);
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)tmp_str);
		break;

	case KMIP_TYPE_BIG_INTEGER:
		rc = kmip_format_bignum(node->big_integer_value, false, &tmp);
		if (rc != 0) {
			kmip_debug(debug, "kmip_format_bignum failed");
			goto out;
		}
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)tmp);
		free(tmp);
		break;

	case KMIP_TYPE_ENUMERATION:
		str = kmip_enum_name_by_tag_value(tag, node->enumeration_value);
		if (str != NULL) {
			attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
					  (xmlChar *)str);
		} else {
			sprintf(tmp_str, "0x%08x", node->enumeration_value);
			attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
					  (xmlChar *)tmp_str);
		}
		break;

	case KMIP_TYPE_BOOLEAN:
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)(node->boolean_value ?
							  "true" : "false"));
		break;

	case KMIP_TYPE_TEXT_STRING:
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)node->text_value);
		break;

	case KMIP_TYPE_BYTE_STRING:
		rc = kmip_format_hex(node->bytes_value, node->length,
				     false, &tmp);
		if (rc != 0) {
			kmip_debug(debug, "kmip_format_hex_long failed");
			goto out;
		}
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)tmp);
		free(tmp);
		break;

	case KMIP_TYPE_DATE_TIME:
		tm = gmtime((time_t *)&node->date_time_value);
		strftime(tmp_str, sizeof(tmp_str), KMIP_ISO8601_TIMESTAMP_UTC,
			 tm);
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)tmp_str);
		break;

	case KMIP_TYPE_DATE_TIME_EXTENDED:
		sprintf(tmp_str, "%ld", node->date_time_ext_value);
		attr = xmlSetProp(ret_xml, (xmlChar *)KMIP_XML_VALUE,
				  (xmlChar *)tmp_str);
		break;

	default:
		kmip_debug(debug, "unknown type: 0x%x", node->type);
		rc = -EINVAL;
		goto out;
	}

	if (attr == NULL && node->type != KMIP_TYPE_STRUCTURE) {
		kmip_debug(debug, "Failed to add '%s' "
			   "attribute to XML node",
			   KMIP_XML_VALUE);
		rc = -ENOMEM;
		goto out;
	}

	rc = 0;
	*xml = ret_xml;

out:
	if (rc != 0)
		xmlFreeNode(ret_xml);

	return rc;
}

#endif
#endif
