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
#include <stdio.h>
#include <string.h>

#include "kmip.h"
#include "names.h"

/**
 * Constructs a Template Attribute node (KMIP v1.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Template-Attribute            Yes       Structure     v1.x only
 *     Name                        No        Structure     v1.x only
 *        ... may be repeated
 *     Attribute                   No        Structure     v1.x only
 *        ... may be repeated
 *
 * Also applies to Common Template-Attribute, Private Key Template-Attribute,
 * Public Key Template-Attribute.
 *
 * @param tag               the template-attribute tag
 * @param num_names         the number of names in the array (can be 0)
 * @param names             array of name nodes
 * @param num_attrs         the number of attributes in the array (can be 0)
 * @param attrs             array of attribute nodes
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
static struct kmip_node *kmip_new_template_attribute_v1(
						enum kmip_tag tag,
						unsigned int num_names,
						struct kmip_node **names,
						unsigned int num_attrs,
						struct kmip_node **attrs)
{
	struct kmip_node *tmpl;
	unsigned int i;
	int rc;

	if (num_names > 0 && names == NULL)
		return NULL;
	if (num_attrs > 0 && attrs == NULL)
		return NULL;

	switch (tag) {
	case KMIP_TAG_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_COMMON_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE:
		break;
	default:
		return NULL;
	}

	tmpl = kmip_node_new_structure_va(KMIP_TAG_TEMPLATE_ATTRIBUTE, NULL, 0);
	if (tmpl == NULL)
		return NULL;

	for (i = 0; i < num_names; i++) {
		rc = kmip_node_add_structure_element(tmpl, names[i]);
		if (rc != 0)
			goto error;
	}

	for (i = 0; i < num_attrs; i++) {
		rc = kmip_node_add_structure_element(tmpl, attrs[i]);
		if (rc != 0)
			goto error;
	}

	return tmpl;

error:
	kmip_node_free(tmpl);
	return NULL;
}

/**
 * Gets information from a Template Attribute node (KMIP v1.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Template-Attribute            Yes       Structure     v1.x only
 *     Name                        No        Structure     v1.x only
 *        ... may be repeated
 *     Attribute                   No        Structure     v1.x only
 *        ... may be repeated
 *
 * Also applies to Common Template-Attribute, Private Key Template-Attribute,
 * Public Key Template-Attribute.
 *
 * @param node              the KMIP node
 * @param num_names         On return: The number of names (can be NULL)
 * @param name_index        the index of the name item to return
 * @param name              On return: the name item of the specified index.
 *                          Function returns -ENOENT if no name is available.
 *                          Can be NULL, then no name entry is returned.
 * @param num_attrs         On return: The number of attributes (can be NULL)
 * @param attr_index        the index of the attribute item to return
 * @param attr              On return: the attribute item of the specified
 *                          index. Function returns -ENOENT if no attribute is
 *                          available. Can be NULL, then no attribute entry is
 *                          returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
static int kmip_get_template_attribute_v1(const struct kmip_node *node,
					  unsigned int *num_names,
					  unsigned int name_index,
					  struct kmip_node **name,
					  unsigned int *num_attrs,
					  unsigned int attr_index,
					  struct kmip_node **attr)
{
	if (node == NULL)
		return -EINVAL;

	switch (kmip_node_get_tag(node)) {
	case KMIP_TAG_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_COMMON_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE:
		break;
	default:
		return -EBADMSG;
	}

	if (num_names != NULL)
		*num_names = kmip_node_get_structure_element_by_tag_count(
						node, KMIP_TAG_NAME);

	if (name != NULL) {
		*name = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_NAME, name_index);
		if (*name == NULL)
			return -ENOENT;
	}

	if (num_attrs != NULL)
		*num_attrs = kmip_node_get_structure_element_by_tag_count(
						node, KMIP_TAG_ATTRIBUTE);

	if (attr != NULL) {
		*attr = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_ATTRIBUTE, attr_index);
		if (*attr == NULL) {
			if (name != NULL && *name != NULL) {
				kmip_node_free(*name);
				*name = NULL;
			}
			return -ENOENT;
		}
	}

	return 0;
}

/**
 * Constructs an Attribute node (KMIP v1.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute                     Yes       Structure     v1.x only
 *     Attribute Name              Yes       Text String   v1.x only
 *     Attribute Index             No        Integer       v1.x only
 *     Attribute Value             Yes       <varies>      v1.x only
 *
 * @param name              the name of the attribute
 * @param index             the index of the attribute. If < 0 then this field
 *                          is omitted
 * @param value             the attribute value node
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
static struct kmip_node *kmip_new_attribute_v1(const char *name, int32_t index,
					       struct kmip_node *value)
{
	struct kmip_node *attr = NULL, *nam, *idx = NULL;

	if (name == NULL || value == NULL)
		return NULL;

	nam = kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_NAME, NULL, name);

	if (index >= 0)
		idx = kmip_node_new_integer(KMIP_TAG_ATTRIBUTE_INDEX, NULL,
					    index);

	if (nam == NULL || (index >= 0 && idx == NULL))
		goto out;

	attr = kmip_node_new_structure_va(KMIP_TAG_ATTRIBUTE, NULL, 3, nam, idx,
					  value);

out:
	kmip_node_free(nam);
	kmip_node_free(idx);

	return attr;
}

/**
 * Gets the information from an Attribute node (KMIP v1.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute                     Yes       Structure     v1.x only
 *     Attribute Name              Yes       Text String   v1.x only
 *     Attribute Index             No        Integer       v1.x only
 *     Attribute Value             Yes       <varies>      v1.x only
 *
 * @param node              the KMIP node
 * @param name              On return: the attribute name (can be NULL)
 * @param index             On return: the attribute index (can be NULL)
 * @param value             On return: the attribute value (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
static int kmip_get_attribute_v1(const struct kmip_node *node,
				 const char **name, int32_t *index,
				 struct kmip_node **value)
{
	struct kmip_node *nam, *idx, *val;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_ATTRIBUTE)
		return -EBADMSG;

	nam = kmip_node_get_structure_element_by_tag(node,
						     KMIP_TAG_ATTRIBUTE_NAME,
						     0);
	idx = kmip_node_get_structure_element_by_tag(node,
						     KMIP_TAG_ATTRIBUTE_INDEX,
						     0);
	val = kmip_node_get_structure_element_by_tag(node,
						     KMIP_TAG_ATTRIBUTE_VALUE,
						     0);
	if (nam == NULL || val == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	if (name != NULL)
		*name = kmip_node_get_text_string(nam);
	if (index != NULL)
		*index = (idx != NULL ? kmip_node_get_integer(idx) : 0);
	if (value != NULL)
		*value =  val;

out:
	kmip_node_free(nam);
	kmip_node_free(idx);
	if (value == NULL || rc != 0)
		kmip_node_free(val);

	return rc;
}

/**
 * Constructs a (Vendor) Attribute node (KMIP v2.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute                     Yes       Structure     v2.x only
 *     Vendor Identification       Yes       Text String   v2.x only
 *     Attribute Name              Yes       Text String   v2.x only
 *     Attribute Value             Yes       <varies>      v2.x only
 *
 * @param vendor_id         the vendor identification of the attribute
 * @param name              the name of the attribute
 * @param value             the attribute value node
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_vendor_attribute(const char *vendor_id,
					    const char *name,
					    struct kmip_node *value)
{
	struct kmip_node *attr = NULL, *nam, *vend = NULL;

	if (vendor_id == NULL || name == NULL || value == NULL)
		return NULL;

	vend = kmip_node_new_text_string(KMIP_TAG_VENDOR_IDENTIFICATION, NULL,
					 vendor_id);
	nam = kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_NAME, NULL, name);
	if (nam == NULL || vend == NULL)
		goto out;

	attr = kmip_node_new_structure_va(KMIP_TAG_ATTRIBUTE, NULL, 3, vend,
					  nam, value);

out:
	kmip_node_free(nam);
	kmip_node_free(vend);

	return attr;
}

/**
 * Gets the information from a (Vendor) Attribute node (KMIP v2.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute                     Yes       Structure     v2.x only
 *     Vendor Identification       Yes       Text String   v2.x only
 *     Attribute Name              Yes       Text String   v2.x only
 *     Attribute Value             Yes       <varies>      v2.x only
 *
 * @param node              the KMIP node
 * @param vendor_id         On return: the vendor identification (can be NULL)
 * @param name              On return: the attribute name (can be NULL)
 * @param value             On return: the attribute value (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_vendor_attribute(const struct kmip_node *node,
			      const char **vendor_id, const char **name,
			      struct kmip_node **value)
{
	struct kmip_node *vend, *nam, *val;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_ATTRIBUTE)
		return -EBADMSG;

	vend = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_VENDOR_IDENTIFICATION, 0);
	nam = kmip_node_get_structure_element_by_tag(node,
						     KMIP_TAG_ATTRIBUTE_NAME,
						     0);
	val = kmip_node_get_structure_element_by_tag(node,
						     KMIP_TAG_ATTRIBUTE_VALUE,
						     0);
	if (vend == NULL || nam == NULL || val == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	if (vendor_id != NULL)
		*vendor_id = kmip_node_get_text_string(vend);
	if (name != NULL)
		*name = kmip_node_get_text_string(nam);
	if (value != NULL)
		*value =  val;

out:
	kmip_node_free(vend);
	kmip_node_free(nam);
	if (value == NULL || rc != 0)
		kmip_node_free(val);

	return rc;
}

/**
 * Constructs an Attributes node (KMIP v2.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attributes                    Yes       Structure     v2.x only
 *     <any attribute>             No        <varies>      v2.x only
 *       ... may be repeated
 *
 * Also applies to Common Attributes, Private Key Attributes,
 * Public Key Attributes
 *
 * @param tag               the attributes tag
 * @param attrs_count       the number of attributes following (can be 0)
 * @param attrs             the array of attributes
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
static struct kmip_node *kmip_new_attributes_v2(enum kmip_tag tag,
						unsigned int attrs_count,
						struct kmip_node **attrs)
{
	switch (tag) {
	case KMIP_TAG_ATTRIBUTES:
	case KMIP_TAG_COMMON_ATTRIBUTES:
	case KMIP_TAG_PRIVATE_KEY_ATTRIBUTES:
	case KMIP_TAG_PUBLIC_KEY_ATTRIBUTES:
		break;
	default:
		return NULL;
	}

	return kmip_node_new_structure(KMIP_TAG_ATTRIBUTES, NULL, attrs_count,
				       attrs);

}

/**
 * Gets the information from an Attributes node (KMIP v2.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attributes                    Yes       Structure     v2.x only
 *     <any attribute>             No        <varies>      v2.x only
 *       ... may be repeated
 *
 * Also applies to Common Attributes, Private Key Attributes,
 * Public Key Attributes
 *
 * @param node              the KMIP node
 * @param num_attrs         On return: The number of attributes (can be NULL)
 * @param attr_index        the index of the attribute to return
 * @param value             On return: the attribute item of the specified
 *                          index. Function returns -ENOENT if no attribute is
 *                          available. Can be NULL, then no attribute entry is
 *                          returned.
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
static int kmip_get_attributes_v2(const struct kmip_node *node,
				  unsigned int *num_attrs,
				  unsigned int attr_index,
				  struct kmip_node **attr)
{
	if (node == NULL)
		return -EINVAL;

	switch (kmip_node_get_tag(node)) {
	case KMIP_TAG_ATTRIBUTES:
	case KMIP_TAG_COMMON_ATTRIBUTES:
	case KMIP_TAG_PRIVATE_KEY_ATTRIBUTES:
	case KMIP_TAG_PUBLIC_KEY_ATTRIBUTES:
		break;
	default:
		return -EBADMSG;
	}

	if (num_attrs != NULL)
		*num_attrs = kmip_node_get_structure_element_count(node);

	if (attr == NULL)
		return 0;

	*attr = kmip_node_get_structure_element_by_index(node, attr_index);
	if (*attr == NULL)
		return -ENOENT;

	return 0;
}

/**
 * Split a KMIP v1.x custom attribute name into a vendor-id and attribute
 * name for a KMIP v2.x vendor attribute.
 *
 * @param name              the custom attribute name. This string is being
 *                          modified during splitting. If the contents is still
 *                          needed, the caller should copy it first.
 * @param vendor_id         On return: the vendor-ID string. This point to
 *                          inside the passed name string from the 1st argument.
 * @param attr_name         On return: the vendor attribute name string.
 *                          This point to  inside the passed name string from
 *                          the 1st argument.
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
static int kmip_split_v1_custom_attr_name(char *name, char **vendor_id,
					  char **attr_name)
{
	char *tok;

	if (name == NULL || vendor_id == NULL || attr_name == NULL)
		return -EINVAL;

	/*
	 * KMIP v1.x custom attribute names in the form 'x|y-<vendor>-<name>'
	 * are transformed into a KMIP v2.x vendor attribute with vendor id
	 * <vendor> and name <name>. If no vendor id is found, then the vendor
	 * id is set to 'x' or 'y', and the name is the remaining name string.
	 */
	if (strncmp(name, "x-", 2) != 0 &&  strncmp(name, "y-", 2) != 0)
		return -EBADMSG;

	name[1] = 0;
	tok = strchr(name + 2, '-');
	if (tok != NULL) {
		*tok = 0;
		*vendor_id = name + 2;
		*attr_name = tok + 1;
	} else {
		*vendor_id = name;
		*attr_name = name + 2;
	}

	return 0;
}

/**
 * Builds a KMIP v1.x custom attribute name from a KMIP v2.x vendor-id and
 * attribute name.
 *
 * @param vendor_id         the vendor-ID string
 * @param attr_name         the vendor attribute name string
 *
 * @returns a newly allocated custom attribute name string, or NULL in case of
 * an error. The returned string must be freed by the caller.
 */
char *kmip_build_v1_custom_attr_name(const char *vendor_id,
				     const char *attr_name)
{
	char *custom_name = NULL;
	int rc;

	if (vendor_id == NULL || attr_name == NULL)
		return NULL;

	if (strcmp(vendor_id, "x") == 0 ||
	    strcmp(vendor_id, "y") == 0)
		rc = asprintf(&custom_name, "%s-%s",
			      vendor_id, attr_name);
	else
		rc = asprintf(&custom_name, "x-%s-%s",
			      vendor_id, attr_name);

	if (rc <= 0 || custom_name == NULL)
		return NULL;

	return custom_name;
}

/**
 * Converts a KMIP v1.x Attribute into a KMIP v2.x Attribute
 *
 * @param v1_attr           the KMIP v1.x attribute to convert
 * @param v2_attr           On return: the KMIP v2.x attribute
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_v2_attr_from_v1_attr(struct kmip_node *v1_attr,
			      struct kmip_node **v2_attr)
{
	char *copy, *vendor_id, *attr_name;
	struct kmip_node *value, *cloned_value;
	enum kmip_tag v2_tag;
	const char *name;
	int rc;

	if (v1_attr == NULL || v2_attr == NULL)
		return -EINVAL;

	rc = kmip_get_attribute_v1(v1_attr, &name, NULL, &value);
	if (rc != 0)
		return rc;

	if (strncmp(name, "x-", 2) == 0 ||
	    strncmp(name, "y-", 2) == 0) {
		/* Special handling for Custom Attribute */
		copy = strdup(name);
		if (copy == NULL) {
			kmip_node_free(value);
			return -ENOMEM;
		}

		rc = kmip_split_v1_custom_attr_name(copy, &vendor_id,
						    &attr_name);
		if (rc != 0) {
			kmip_node_free(value);
			free(copy);
			return rc;
		}

		cloned_value = kmip_node_clone(value);
		kmip_node_free(value);
		if (cloned_value == NULL) {
			free(copy);
			return -ENOMEM;
		}
		*v2_attr = kmip_new_vendor_attribute(vendor_id, attr_name,
						     cloned_value);
		free(copy);
		kmip_node_free(cloned_value);
		return 0;
	}

	v2_tag = kmip_attr_tag_by_v1_attr_name(name);
	if (v2_tag == 0) {
		kmip_node_free(value);
		return -EBADMSG;
	}

	cloned_value = kmip_node_clone(value);
	kmip_node_free(value);
	if (cloned_value == NULL)
		return -ENOMEM;

	cloned_value->tag = v2_tag;
	*v2_attr = cloned_value;

	return 0;
}

/**
 * Converts a KMIP v2.x Attribute into a KMIP v1.x Attribute
 *
 * @param v2_attr           the KMIP v2.x attribute to convert
 * @param v1_attr           On return: the KMIP v1.x attribute
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_v1_attr_from_v2_attr(struct kmip_node *v2_attr,
			      struct kmip_node **v1_attr)
{
	struct kmip_node *attr_value, *cloned_value;
	const char *attr_name, *vendor_id;
	char *custom_name;
	int rc;

	if (v2_attr == NULL || v1_attr == NULL)
		return -EINVAL;

	if (v2_attr->tag == KMIP_TAG_ATTRIBUTE) {
		/* Special handling for v2.x Vendor Attribute */
		rc = kmip_get_vendor_attribute(v2_attr, &vendor_id,
					       &attr_name, &attr_value);
		if (rc != 0)
			return rc;

		custom_name = kmip_build_v1_custom_attr_name(vendor_id,
							     attr_name);
		if (custom_name == NULL) {
			kmip_node_free(attr_value);
			return -EBADMSG;
		}

		cloned_value = kmip_node_clone(attr_value);
		kmip_node_free(attr_value);
		if (cloned_value == NULL) {
			free(custom_name);
			return -ENOMEM;
		}

		*v1_attr = kmip_new_attribute_v1(custom_name, -1, cloned_value);
		kmip_node_free(cloned_value);
		free(custom_name);
		if (*v1_attr == NULL)
			return -ENOMEM;

		return 0;
	}

	attr_name = kmip_v1_attr_name_by_tag(v2_attr->tag);
	if (attr_name == NULL)
		return -EBADMSG;

	cloned_value = kmip_node_clone(v2_attr);
	if (cloned_value == NULL)
		return -ENOMEM;

	/* Modify the cloned v2 attr and use it as value of the v1 attr */
	cloned_value->tag = KMIP_TAG_ATTRIBUTE_VALUE;
	*v1_attr = kmip_new_attribute_v1(attr_name, -1, cloned_value);
	kmip_node_free(cloned_value);
	if (*v1_attr == NULL)
		return -ENOMEM;

	return 0;
}

/**
 * Constructs an Attributes node (KMIP v2.x) or a Template Attribute node
 * (KMIP v1.x) from a list of attributes in KMIP v2.x style, dependent on the
 * protocol version specified:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attributes                    Yes       Structure     v2.x only
 *     <any attribute>             No        <varies>      v2.x only
 *       ... may be repeated
 *
 * Also applies to Common Attributes, Private Key Attributes,
 * Public Key Attributes
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Template-Attribute            Yes       Structure     v1.x only
 *     Name                        No        Structure     v1.x only
 *        ... may be repeated
 *     Attribute                   No        Structure     v1.x only
 *        ... may be repeated
 *
 * Also applies to Common Template-Attribute, Private Key Template-Attribute,
 * Public Key Template-Attribute.
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param v2_tag            the attributes tag
 * @param attrs_count       the number of attributes following
 * @param v2_attrs           the array of attributes (as KMIP v2.x attributes)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_attributes(const struct kmip_version *version,
				      enum kmip_tag v2_tag,
				      unsigned int attrs_count,
				      struct kmip_node **v2_attrs)
{
	struct kmip_node *attrs = NULL, *attr;
	struct kmip_node **v1_attrs = NULL;
	enum kmip_tag v1_tag = 0;
	unsigned int i;
	int rc;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	if (version->major == 1) {
		/* KMIP v1.x: translate v1-tag to v2-tag */
		switch (v2_tag) {
		case KMIP_TAG_ATTRIBUTES:
			v1_tag = KMIP_TAG_TEMPLATE_ATTRIBUTE;
			break;
		case KMIP_TAG_COMMON_ATTRIBUTES:
			v1_tag = KMIP_TAG_COMMON_TEMPLATE_ATTRIBUTE;
			break;
		case KMIP_TAG_PRIVATE_KEY_ATTRIBUTES:
			v1_tag = KMIP_TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE;
			break;
		case KMIP_TAG_PUBLIC_KEY_ATTRIBUTES:
			v1_tag = KMIP_TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE;
			break;
		default:
			return NULL;
		}

		if (attrs_count > 0) {
			v1_attrs = calloc(attrs_count,
					  sizeof(struct kmip_node *));
			if (v1_attrs == NULL)
				return NULL;
		}

		for (i = 0; i < attrs_count; i++) {
			attr = v2_attrs[i];
			if (attr == NULL)
				goto error;

			rc = kmip_v1_attr_from_v2_attr(attr, &v1_attrs[i]);
			if (rc != 0)
				goto error;
		}

		attrs = kmip_new_template_attribute_v1(v1_tag, 0, NULL,
						       attrs_count, v1_attrs);

error:
		for (i = 0; i < attrs_count; i++) {
			if (v1_attrs[i] == NULL)
				continue;
			kmip_node_free(v1_attrs[i]);
		}
		if (v1_attrs != NULL)
			free(v1_attrs);
	} else {
		/* KMIP >= v2.0 */
		attrs = kmip_new_attributes_v2(v2_tag, attrs_count, v2_attrs);
	}

	return attrs;
}

/**
 * Constructs an Attributes node (KMIP v2.x) or a Template Attribute node
 * (KMIP v1.x) from a list of attributes in KMIP v2.x style, dependent on the
 * protocol version specified:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attributes                    Yes       Structure     v2.x only
 *     <any attribute>             No        <varies>      v2.x only
 *       ... may be repeated
 *
 * Also applies to Common Attributes, Private Key Attributes,
 * Public Key Attributes
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Template-Attribute            Yes       Structure     v1.x only
 *     Name                        No        Structure     v1.x only
 *        ... may be repeated
 *     Attribute                   No        Structure     v1.x only
 *        ... may be repeated
 *
 * Also applies to Common Template-Attribute, Private Key Template-Attribute,
 * Public Key Template-Attribute.
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param v2_tag            the attributes tag
 * @param attrs_count       the number of attributes following
 * @param <attributes>      the attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_attributes_va(const struct kmip_version *version,
					 enum kmip_tag v2_tag,
					 unsigned int attrs_count, ...)
{
	struct kmip_node *ret, **attrs = NULL;
	unsigned int i, k;
	va_list ap;

	if (attrs_count > 0) {
		attrs = calloc(attrs_count, sizeof(struct kmip_node *));
		if (attrs == NULL)
			return NULL;
	}

	va_start(ap, attrs_count);
	for (i = 0, k = 0; i < attrs_count; i++) {
		attrs[k] = va_arg(ap, struct kmip_node *);
		if (attrs[k] != NULL)
			k++;
	}
	va_end(ap);

	ret = kmip_new_attributes(version, v2_tag, k, attrs);
	if (attrs != NULL)
		free(attrs);

	return ret;
}

/**
 * Gets the information from an Attributes node (KMIP v2.x) or a Template
 * Attribute node (KMIP v1.x). The returned attribute is always in KMIP v2.x
 * style.
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attributes                    Yes       Structure     v2.x only
 *     <any attribute>             No        <varies>      v2.x only
 *       ... may be repeated
 *
 * Also applies to Common Attributes, Private Key Attributes,
 * Public Key Attributes
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Template-Attribute            Yes       Structure     v1.x only
 *     Name                        No        Structure     v1.x only
 *        ... may be repeated
 *     Attribute                   No        Structure     v1.x only
 *        ... may be repeated
 *
 * Also applies to Common Template-Attribute, Private Key Template-Attribute,
 * Public Key Template-Attribute.
 *
 * @param node              the KMIP node
 * @param num_attrs         On return: the number of attributes (can be NULL).
 * @param attr_index        the index of the attribute to return
 * @param value             On return: the attribute item of the specified index
 *                          (as a KMIP v2.x attribute).
 *                          Function returns -ENOENT if no attribute is
 *                          available. Can be NULL, then no attribute entry is
 *                          returned.
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_attributes(const struct kmip_node *node, unsigned int *num_attrs,
			unsigned int attr_index, struct kmip_node **attr)
{
	struct kmip_node *v1_attr, *v2_attr;
	int rc;

	if (node == NULL)
		return -EINVAL;

	switch (kmip_node_get_tag(node)) {
	case KMIP_TAG_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_COMMON_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE:
	case KMIP_TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE:
		/* KMIP v1.x template attributes */
		if (attr == NULL) {
			rc = kmip_get_template_attribute_v1(node, NULL, 0, NULL,
							    num_attrs, 0, NULL);
			return rc;
		}

		rc = kmip_get_template_attribute_v1(node, NULL, 0, NULL,
						    num_attrs, attr_index,
						    &v1_attr);
		if (rc != 0)
			return rc;

		rc = kmip_v2_attr_from_v1_attr(v1_attr, &v2_attr);
		kmip_node_free(v1_attr);
		if (rc != 0)
			return rc;

		*attr = v2_attr;
		break;

	case KMIP_TAG_ATTRIBUTES:
	case KMIP_TAG_COMMON_ATTRIBUTES:
	case KMIP_TAG_PRIVATE_KEY_ATTRIBUTES:
	case KMIP_TAG_PUBLIC_KEY_ATTRIBUTES:
		/* KMIP v2.x attributes */
		rc = kmip_get_attributes_v2(node, num_attrs, attr_index, attr);
		if (rc != 0)
			return rc;
		break;

	default:
		return -EBADMSG;
	}

	return 0;
}

/**
 * Constructs an Attribute Reference node (KMIP v2.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute Reference           Yes       Enumeration   v2.x only
 * or
 *   Attribute Reference           Yes       Structure     v2.x only
 *     Vendor Identification       Yes       Text String   v2.x only
 *     Attribute Name              Yes       Text String   v2.x only
 *
 * @param attr_tag          the attribute tag
 * @param vendor_id         the vendor identification of the attribute
 * @param name              the name of the attribute
 *
 * Either the attr_tag or the vendor_id and name can be specified, but not both.
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_attribute_reference(enum kmip_tag attr_tag,
					       const char *vendor_id,
					       const char *name)
{
	struct kmip_node *ref = NULL, *nam, *vend = NULL;

	if (attr_tag == 0 && (vendor_id == NULL || name == NULL))
		return NULL;
	if (attr_tag != 0 && (vendor_id != NULL || name != NULL))
		return NULL;

	if (attr_tag != 0)
		return kmip_node_new_enumeration(KMIP_TAG_ATTRIBUTE_REFERENCE,
						 NULL, attr_tag);

	vend = kmip_node_new_text_string(KMIP_TAG_VENDOR_IDENTIFICATION, NULL,
					 vendor_id);
	nam = kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_NAME, NULL, name);
	if (nam == NULL || vend == NULL)
		goto out;

	ref = kmip_node_new_structure_va(KMIP_TAG_ATTRIBUTE_REFERENCE, NULL,
					 2, vend, nam);

out:
	kmip_node_free(nam);
	kmip_node_free(vend);

	return ref;
}

/**
 * Gets the information from a Attribute Reference node (KMIP v2.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute Reference           Yes       Enumeration   v2.x only
 * or
 *   Attribute Reference           Yes       Structure     v2.x only
 *     Vendor Identification       Yes       Text String   v2.x only
 *     Attribute Name              Yes       Text String   v2.x only
 *
 * @param node              the KMIP node
 * @param attr_tag          On return: The attribute tag (can be NULL)
 * @param vendor_id         On return: the vendor identification (can be NULL)
 * @param name              On return: the attribute name (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_attribute_reference(const struct kmip_node *node,
				 enum kmip_tag *attr_tag,
				 const char **vendor_id, const char **name)
{
	struct kmip_node *vend, *nam;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_ATTRIBUTE_REFERENCE)
		return -EBADMSG;

	if (kmip_node_get_type(node) == KMIP_TYPE_ENUMERATION) {
		if (attr_tag != NULL)
			*attr_tag = kmip_node_get_enumeration(node);

		if (vendor_id != NULL)
			vendor_id = NULL;
		if (name != NULL)
			*name = NULL;

		return 0;
	}

	if (kmip_node_get_type(node) != KMIP_TYPE_STRUCTURE)
		return -EBADMSG;

	if (attr_tag != NULL)
		*attr_tag = 0;

	vend = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_VENDOR_IDENTIFICATION, 0);
	nam = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_ATTRIBUTE_NAME, 0);
	if (vend == NULL || nam == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	if (vendor_id != NULL)
		*vendor_id = kmip_node_get_text_string(vend);
	if (name != NULL)
		*name = kmip_node_get_text_string(nam);

out:
	kmip_node_free(vend);
	kmip_node_free(nam);

	return rc;
}

/**
 * Constructs an Current or New Attribute node (KMIP v2.x):
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Current Attribute             Yes       Structure     v2.x only
 * or
 *   New Attribute                 Yes       Structure     v2.x only
 *
 * @param new_attr          if true a New Attribute structure, if false a
 *                          Current Attribute structure is created
 * @param attr              the KMIP v2.x attribute
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_current_new_attribute(bool new_attr,
						 struct kmip_node *attr)
{
	enum kmip_tag tag;

	if (attr == NULL)
		return NULL;

	tag = (new_attr ? KMIP_TAG_NEW_ATTRIBUTE : KMIP_TAG_CURRENT_ATTRIBUTE);
	return kmip_node_new_structure_va(tag, NULL, 1, attr);
}

/**
 * Constructs an Attribute Name node (KMIP v1.x) from a KMIP v2.x Attribute
 * Reference:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute Name                Yes       Text String   v1.x only
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute Reference           Yes       Enumeration   v2.x only
 * or
 *   Attribute Reference           Yes       Structure     v2.x only
 *     Vendor Identification       Yes       Text String   v2.x only
 *     Attribute Name              Yes       Text String   v2.x only
 *
 * @param v2_attr_ref      the attribute reference node (as of KMIP v2.x)
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_attribute_name_v1(
					const struct kmip_node *v2_attr_ref)
{
	const char *vendor_id = NULL, *attr_name = NULL;
	enum kmip_tag attr_tag = 0;
	struct kmip_node *ret;
	char *name = NULL;
	int rc;

	rc = kmip_get_attribute_reference(v2_attr_ref, &attr_tag, &vendor_id,
					  &attr_name);
	if (rc != 0)
		return NULL;

	if (attr_tag != 0) {
		attr_name = kmip_v1_attr_name_by_tag(attr_tag);
		if (attr_name == NULL)
			return NULL;

		return kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_NAME, NULL,
						 attr_name);
	}

	if (vendor_id == NULL || attr_name == NULL)
		return NULL;

	/* Special handling for v2.x Vendor Attribute */
	name = kmip_build_v1_custom_attr_name(vendor_id, attr_name);
	if (name == NULL)
		return NULL;

	ret =  kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_NAME, NULL, name);
	free(name);
	return ret;
}

/**
 * Gets the information from an Attribute Name node (KMIP v1.x) and returns
 * a KMIP v2.x Attribute Reference:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute Name                Yes       Text String   v1.x only
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Attribute Reference           Yes       Enumeration   v2.x only
 * or
 *   Attribute Reference           Yes       Structure     v2.x only
 *     Vendor Identification       Yes       Text String   v2.x only
 *     Attribute Name              Yes       Text String   v2.x only
 *
 * @param node              the KMIP node
 * @param v2_attr_ref       On return: the attribute reference node (as of
 *                          KMIP v2.x)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_attribute_name_v1(const struct kmip_node *node,
			       struct kmip_node **v2_attr_ref)
{
	char *copy, *vendor_id, *attr_name;
	enum kmip_tag attr_tag;
	const char *name;
	int rc;

	if (node == NULL || v2_attr_ref == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_ATTRIBUTE_NAME)
		return -EBADMSG;

	name = kmip_node_get_text_string(node);
	if (name == NULL)
		return -EBADMSG;

	if (strncmp(name, "x-", 2) == 0 || strncmp(name, "y-", 2) == 0) {
		/* Special handling for Custom Attribute */
		copy = strdup(name);
		if (copy == NULL)
			return -ENOMEM;

		rc = kmip_split_v1_custom_attr_name(copy, &vendor_id,
						    &attr_name);
		if (rc != 0) {
			free(copy);
			return rc;
		}

		*v2_attr_ref = kmip_new_attribute_reference(0, vendor_id,
							    attr_name);
		free(copy);

		if (*v2_attr_ref == NULL)
			return -ENOMEM;

		return 0;
	}

	attr_tag = kmip_attr_tag_by_v1_attr_name(name);
	if (attr_tag == 0)
		return -EBADMSG;

	*v2_attr_ref = kmip_new_attribute_reference(attr_tag, NULL, NULL);
	if (*v2_attr_ref == NULL)
		return -ENOMEM;

	return 0;
}

/**
 * Constructs a Unique Identifier attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Unique Identifier             Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param text_id           the unique identifier as text string (or NULL)
 * @param enum_id           the unique identifier as enumeration (or 0)
 * @param int_id            the unique identifier as integer
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_unique_identifier(const char *text_id,
					enum kmip_unique_identifier enum_id,
					int32_t int_id)
{
	if (text_id != NULL && enum_id != 0)
		return NULL;

	if (text_id != NULL)
		return kmip_node_new_text_string(KMIP_TAG_UNIQUE_IDENTIFIER,
						 NULL, text_id);
	if (enum_id != 0)
		return kmip_node_new_enumeration(KMIP_TAG_UNIQUE_IDENTIFIER,
						 NULL, enum_id);

	return kmip_node_new_integer(KMIP_TAG_UNIQUE_IDENTIFIER, NULL, int_id);
}

/**
 * Gets the information from a Unique Identifier attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Unique Identifier             Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param text_id           the unique identifier as text string (can be NULL)
 * @param enum_id           the unique identifier as enumeration (can be NULL)
 * @param int_id            the unique identifier as integer (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_unique_identifier(const struct kmip_node *node,
			       const char **text_id,
			       enum kmip_unique_identifier *enum_id,
			       int32_t *int_id)
{
	if (node == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_UNIQUE_IDENTIFIER)
		return -EBADMSG;

	if (text_id != NULL) {
		if (kmip_node_get_type(node) == KMIP_TYPE_TEXT_STRING)
			*text_id = kmip_node_get_text_string(node);
		else
			*text_id = NULL;
	}

	if (enum_id != NULL) {
		if (kmip_node_get_type(node) == KMIP_TYPE_ENUMERATION)
			*enum_id = kmip_node_get_enumeration(node);
		else
			*enum_id = 0;
	}

	if (int_id != NULL) {
		if (kmip_node_get_type(node) == KMIP_TYPE_INTEGER)
			*int_id = kmip_node_get_integer(node);
		else
			*int_id = 0;
	}

	return 0;
}

/**
 * Constructs a Name attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Name                          Yes       Structure     v1.0
 *     Name Value                  Yes       Text String   v1.0
 *     Name Type                   Yes       Enumeration   v1.0
 *
 * @param value             the value of the name
 * @param type              the type of the name
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_name(const char *value, enum kmip_name_type type)
{
	struct kmip_node *name = NULL, *val, *typ;

	if (value == NULL)
		return NULL;

	val = kmip_node_new_text_string(KMIP_TAG_NAME_VALUE, NULL, value);
	typ = kmip_node_new_enumeration(KMIP_TAG_NAME_TYPE, NULL, type);

	if (val == NULL || typ == NULL)
		goto out;

	name = kmip_node_new_structure_va(KMIP_TAG_NAME, NULL, 2, val, typ);

out:
	kmip_node_free(val);
	kmip_node_free(typ);

	return name;
}

/**
 * Gets the information from a Name attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Name                          Yes       Structure     v1.0
 *     Name Value                  Yes       Text String   v1.0
 *     Name Type                   Yes       Enumeration   v1.0
 *
 * @param node              the KMIP node
 * @param value             On return: the name value (can be NULL)
 * @param type              On return: the name type (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_name(const struct kmip_node *node,
		  const char **value, enum kmip_name_type *type)
{
	struct kmip_node *val, *typ;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_NAME)
		return -EBADMSG;

	val = kmip_node_get_structure_element_by_tag(node, KMIP_TAG_NAME_VALUE,
						     0);
	typ = kmip_node_get_structure_element_by_tag(node, KMIP_TAG_NAME_TYPE,
						     0);
	if (val == NULL || typ == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	if (value != NULL)
		*value = kmip_node_get_text_string(val);
	if (type != NULL)
		*type = kmip_node_get_enumeration(typ);

out:
	kmip_node_free(val);
	kmip_node_free(typ);

	return rc;
}

/**
 * Constructs a Alternative Name attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Alternative Name              Yes       Structure     v1.2
 *     Alternative Name Value      Yes       Text String   v1.2
 *     Alternative Name Type       Yes       Enumeration   v1.2
 *
 * @param value             the value of the alternative name
 * @param type              the type of the alternative name
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_alternative_name(const char *value,
					enum kmip_alternative_name_type type)
{
	struct kmip_node *name = NULL, *val, *typ;

	if (value == NULL)
		return NULL;

	val = kmip_node_new_text_string(KMIP_TAG_ALTERNATE_NAME_VALUE, NULL,
					value);
	typ = kmip_node_new_enumeration(KMIP_TAG_ALTERNATE_NAME_TYPE, NULL,
					type);

	if (val == NULL || typ == NULL)
		goto out;

	name = kmip_node_new_structure_va(KMIP_TAG_ALTERNATE_NAME, NULL, 2, val,
					  typ);

out:
	kmip_node_free(val);
	kmip_node_free(typ);

	return name;
}

/**
 * Gets the information from an Alternative Name attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Alternative Name              Yes       Structure     v1.2
 *     Alternative Name Value      Yes       Text String   v1.2
 *     Alternative Name Type       Yes       Enumeration   v1.2
 *
 * @param node              the KMIP node
 * @param value             On return: the alternative name value (can be NULL)
 * @param type              On return: the alternative name type (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_alternative_name(const struct kmip_node *node,
			      const char **value,
			      enum kmip_alternative_name_type *type)
{
	struct kmip_node *val, *typ;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_ALTERNATE_NAME)
		return -EBADMSG;

	val = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_ALTERNATE_NAME_VALUE, 0);
	typ = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_ALTERNATE_NAME_TYPE, 0);
	if (val == NULL || typ == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	if (value != NULL)
		*value = kmip_node_get_text_string(val);
	if (type != NULL)
		*type = kmip_node_get_enumeration(typ);

out:
	kmip_node_free(val);
	kmip_node_free(typ);

	return rc;
}

/**
 * Constructs a Object Type attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Object Type                   Yes       Enumeration   v1.0
 *
 * @param obj_type          the object type
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_object_type(enum kmip_object_type obj_type)
{
	return kmip_node_new_enumeration(KMIP_TAG_OBJECT_TYPE, NULL, obj_type);
}

/**
 * Gets the information from a Object Type attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Object Type                   Yes       Enumeration   v1.0
 *
 *
 * @param node              the KMIP node
 * @param obj_type          the object type
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_object_type(const struct kmip_node *node,
			 enum kmip_object_type *obj_type)
{
	if (node == NULL || obj_type == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_OBJECT_TYPE)
		return -EBADMSG;

	*obj_type = kmip_node_get_enumeration(node);
	return 0;
}

/**
 * Constructs a Cryptographic Algorithm attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Algorithm       Yes       Enumeration   v1.0
 *
 * @param algo              the cryptographic algorithm
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_cryptographic_algorithm(enum kmip_crypto_algo algo)
{
	return kmip_node_new_enumeration(KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, NULL,
					 algo);
}

/**
 * Gets the information from a Cryptographic Algorithm attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Algorithm       Yes       Enumeration   v1.0
 *
 *
 * @param node              the KMIP node
 * @param algo              the cryptographic algorithm
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_cryptographic_algorithm(const struct kmip_node *node,
				     enum kmip_crypto_algo *algo)
{
	if (node == NULL || algo == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM)
		return -EBADMSG;

	*algo = kmip_node_get_enumeration(node);
	return 0;
}

/**
 * Constructs a Cryptographic Length attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Length          Yes       Integer       v1.0
 *
 * @param length            the cryptographic length
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_cryptographic_length(int32_t length)
{
	return kmip_node_new_integer(KMIP_TAG_CRYPTOGRAPHIC_LENGTH, NULL,
				     length);
}

/**
 * Gets the information from a Cryptographic Length attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Length          Yes       Integer       v1.0
 *
 *
 * @param node              the KMIP node
 * @param length            the cryptographic length
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_cryptographic_length(const struct kmip_node *node,
				  int32_t *length)
{
	if (node == NULL || length == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_CRYPTOGRAPHIC_LENGTH)
		return -EBADMSG;

	*length = kmip_node_get_integer(node);
	return 0;
}

/**
 * Constructs a Certificate Type attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Certificate Type              Yes       Enumeration   v1.0
 *
 * @param type              the certificate type
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_certificate_type(enum kmip_certificate_type type)
{
	return kmip_node_new_enumeration(KMIP_TAG_CERTIFICATE_TYPE, NULL, type);
}

/**
 * Gets the information from a Certificate Type attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Certificate Type              Yes       Enumeration   v1.0
 *
 *
 * @param node              the KMIP node
 * @param type              the certificate type
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_certificate_type(const struct kmip_node *node,
			      enum kmip_certificate_type *type)
{
	if (node == NULL || type == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_CERTIFICATE_TYPE)
		return -EBADMSG;

	*type = kmip_node_get_enumeration(node);
	return 0;
}

/**
 * Constructs a Cryptographic Usage Mask attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Usage Mask      Yes       Integer       v1.0
 *
 * @param usage_mask        the cryptographic usage mask
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_cryptographic_usage_mask(int32_t usage_mask)
{
	return kmip_node_new_integer(KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK, NULL,
				     usage_mask);
}

/**
 * Gets the information from a Cryptographic Usage Mask attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Usage Mask      Yes       Integer       v1.0
 *
 *
 * @param node              the KMIP node
 * @param usage_mask        the cryptographic usage mask
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_cryptographic_usage_mask(const struct kmip_node *node,
				      int32_t *usage_mask)
{
	if (node == NULL || usage_mask == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK)
		return -EBADMSG;

	*usage_mask = kmip_node_get_integer(node);
	return 0;
}

/**
 * Constructs a State attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   State                         Yes       Enumeration   v1.0
 *
 * @param state             the state
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_state(enum kmip_state state)
{
	return kmip_node_new_enumeration(KMIP_TAG_STATE, NULL, state);
}

/**
 * Gets the information from a State attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   State                         Yes       Enumeration   v1.0
 *
 *
 * @param node              the KMIP node
 * @param state             the state
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_state(const struct kmip_node *node, enum kmip_state *state)
{
	if (node == NULL || state == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_STATE)
		return -EBADMSG;

	*state = kmip_node_get_enumeration(node);
	return 0;
}

/**
 * Constructs a Initial Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Initial Date                  Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_initial_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_INITIAL_DATE, NULL, date);
}

/**
 * Gets the information from a Initial Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Initial Date                  Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_initial_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_INITIAL_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Activation Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Activation Date               Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_activation_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_ACTIVATION_DATE, NULL, date);
}

/**
 * Gets the information from a Activation Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Activation Date               Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_activation_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_ACTIVATION_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Deactivation Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Deactivation Date             Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_deactivation_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_DEACTIVATION_DATE, NULL,
					 date);
}

/**
 * Gets the information from a Deactivation Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Deactivation Date             Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_deactivation_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_DEACTIVATION_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Destroy Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Destroy Date                  Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_destroy_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_DESTROY_DATE, NULL, date);
}

/**
 * Gets the information from a Destroy Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Destroy Date                  Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_destroy_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_DESTROY_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Compromise Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Compromise Date               Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_compromise_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_COMPROMIZE_DATE, NULL, date);
}

/**
 * Gets the information from a Compromise Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Compromise Date               Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_compromise_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_COMPROMIZE_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Compromise Occurrence Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Compromise Occurrence Date    Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_compromise_occurrence_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_COMPROMISE_OCCURRENCE_DATE,
					 NULL, date);
}

/**
 * Gets the information from a Compromise Occurrence Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Compromise Occurrence Date    Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_compromise_occurrence_date(const struct kmip_node *node,
					int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_COMPROMISE_OCCURRENCE_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Last Change Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Last Change Date              Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_last_change_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_LAST_CHANGE_DATE, NULL, date);
}

/**
 * Gets the information from a Last Change Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Last Change Date              Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_last_change_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_LAST_CHANGE_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Original Creation Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Original Creation Date        Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_original_creation_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_ORIGINAL_CREATION_DATE, NULL,
					 date);
}

/**
 * Gets the information from a Original Creation Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Original Creation Date        Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_original_creation_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_ORIGINAL_CREATION_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Archive Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Archive Date                  Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_archive_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_ARCHIVE_DATE, NULL, date);
}

/**
 * Gets the information from a Archive Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Archive Date                  Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_archive_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_ARCHIVE_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Process Start Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Process Start Date            Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_process_start_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_PROCESS_START_DATE, NULL,
					 date);
}

/**
 * Gets the information from a Process Start Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Process Start Date            Yes       Date-Time   v1.0
 *
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_process_start_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_PROCESS_START_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Protect Stop Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protect Stop Date             Yes       Date-Time   v1.0
 *
 * @param date              the date
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_protect_stop_date(int64_t date)
{
	return kmip_node_new_enumeration(KMIP_TAG_PROTECT_STOP_DATE, NULL,
					 date);
}

/**
 * Gets the information from a Protect Stop Date attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protect Stop Date             Yes       Date-Time   v1.0
 *
 * @param node              the KMIP node
 * @param date              the date
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_protect_stop_date(const struct kmip_node *node, int64_t *date)
{
	if (node == NULL || date == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_PROTECT_STOP_DATE)
		return -EBADMSG;

	*date = kmip_node_get_date_time(node);
	return 0;
}

/**
 * Constructs a Cryptographic Parameters attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Parameters                Structure     v1.0
 *     Block Cipher Mode           No        Enumeration   v1.0
 *     Padding Method              No        Enumeration   v1.0
 *     Hashing Algorithm           No        Enumeration   v1.0
 *     Key Role Type               No        Enumeration   v1.0
 *     Digital Signature Algorithm No        Enumeration   v1.2
 *     Cryptographic Algorithm     No        Enumeration   v1.2
 *     Random IV                   No        Boolean       v1.2
 *     IV Length                   No        Integer       v1.2
 *     Tag Length                  No        Integer       v1.2
 *     Fixed Field Length          No        Integer       v1.2
 *     Invocation Field Length     No        Integer       v1.2
 *     Counter Length              No        Integer       v1.2
 *     Initial Counter Value       No        Integer       v1.2
 *     Salt Length                 No        Integer       v1.4
 *     Mask Generator              No        Enumeration   v1.4
 *     Mask Generator Hashing Alg  No        Enumeration   v1.4
 *     P Source                    No        Byte String   v1.4
 *     Trailer Field               No        Integer       v1.4
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param mode              the block cipher mode (ignored if 0)
 * @param padding           the padding method (ignored if 0)
 * @param hash_algo         the hashing algorithm (ignored if 0)
 * @param key_role          the key role type (ignored if 0)
 * @param signature_algo    the signature algorithm (ignored if 0)
 * @param crypto_algo       the cryptographic algorithm (ignored if 0)
 * @param random_iv         true if a random IV is used (ignored if NULL)
 * @param iv_length         the IV length (ignored if NULL)
 * @param tag_length        the tag length (ignored if NULL)
 * @param fixed_field_length the fixed field length (ignored if NULL)
 * @param invoc_field_length the invocation field length (ignored if NULL)
 * @param counter_length    the counter length (ignored if NULL)
 * @param init_counter_value the initial counter value (ignored if NULL)
 * @param salt_length       the salt length (ignored if NULL)
 * @param mgf               the mask generator (ignored if 0)
 * @param mgf_hash_algo     the mask generator hash algorithm (ignored if 0)
 * @param trailer_field     the trailer field (ignored if NULL)
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_cryptographic_parameters(
					const struct kmip_version *version,
					enum kmip_block_cipher_mode mode,
					enum kmip_padding_method padding,
					enum kmip_hashing_algo hash_algo,
					enum kmip_key_role_type key_role,
					enum kmip_signature_algo signature_algo,
					enum kmip_crypto_algo crypto_algo,
					bool *random_iv,
					int32_t *iv_length,
					int32_t *tag_length,
					int32_t *fixed_field_length,
					int32_t *invoc_field_length,
					int32_t *counter_length,
					int32_t *init_counter_value,
					int32_t *salt_length,
					enum kmip_mask_generator mgf,
					enum kmip_hashing_algo mgf_hash_algo,
					int32_t *trailer_field)
{
	struct kmip_node *icv = NULL, *salt = NULL, *mg = NULL, *mghash = NULL;
	struct kmip_node *ret = NULL, *cmod = NULL, *pad = NULL, *hash = NULL;
	struct kmip_node *krl = NULL, *sig = NULL, *algo = NULL, *riv = NULL;
	struct kmip_node *iv = NULL, *tag = NULL, *ffl = NULL, *ifl = NULL;
	struct kmip_node *cnt = NULL, *trl = NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();


	if (mode != 0) {
		cmod = kmip_node_new_enumeration(KMIP_TAG_BLOCK_CIPHER_MODE,
						 NULL, mode);
		if (cmod == NULL)
			goto out;
	}

	if (padding != 0) {
		pad = kmip_node_new_enumeration(KMIP_TAG_PADDING_METHOD,
						NULL, padding);
		if (pad == NULL)
			goto out;
	}

	if (hash_algo != 0) {
		hash = kmip_node_new_enumeration(KMIP_TAG_HASHING_ALGORITHM,
						NULL, hash_algo);
		if (hash == NULL)
			goto out;
	}

	if (key_role != 0) {
		krl = kmip_node_new_enumeration(KMIP_TAG_KEY_ROLE_TYPE,
						NULL, key_role);
		if (krl == NULL)
			goto out;
	}

	if (version->major == 1 && version->minor < 2)
		goto create;

	if (signature_algo != 0) {
		sig = kmip_node_new_enumeration(
				KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM,
				NULL, signature_algo);
		if (sig == NULL)
			goto out;
	}

	if (crypto_algo != 0) {
		algo = kmip_node_new_enumeration(
				KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
				NULL, crypto_algo);
		if (algo == NULL)
			goto out;
	}

	if (random_iv != NULL) {
		riv = kmip_node_new_boolean(KMIP_TAG_RANDOM_IV, NULL,
					    *random_iv);
		if (riv == NULL)
			goto out;
	}

	if (iv_length != NULL) {
		iv = kmip_node_new_integer(KMIP_TAG_IV_LENGTH, NULL,
					    *iv_length);
		if (iv == NULL)
			goto out;
	}

	if (tag_length != NULL) {
		tag = kmip_node_new_integer(KMIP_TAG_TAG_LENGTH, NULL,
					    *tag_length);
		if (tag == NULL)
			goto out;
	}

	if (fixed_field_length != NULL) {
		ffl = kmip_node_new_integer(KMIP_TAG_FIXED_FIELD_LENGTH, NULL,
					    *fixed_field_length);
		if (ffl == NULL)
			goto out;
	}

	if (invoc_field_length != NULL) {
		ifl = kmip_node_new_integer(KMIP_TAG_INVOCATION_FIELD_LENGTH,
					    NULL, *invoc_field_length);
		if (ifl == NULL)
			goto out;
	}


	if (counter_length != NULL) {
		cnt = kmip_node_new_integer(KMIP_TAG_COUNTER_LENGTH, NULL,
					    *counter_length);
		if (cnt == NULL)
			goto out;
	}

	if (init_counter_value != NULL) {
		icv = kmip_node_new_integer(KMIP_TAG_INITIAL_COUNTER_VALUE,
					    NULL, *init_counter_value);
		if (icv == NULL)
			goto out;
	}

	if (version->major == 1 && version->minor < 4)
		goto create;

	if (salt_length != NULL) {
		salt = kmip_node_new_integer(KMIP_TAG_SALT_LENGTH, NULL,
					    *salt_length);
		if (salt == NULL)
			goto out;
	}

	if (mgf != 0) {
		mg = kmip_node_new_enumeration(KMIP_TAG_MASK_GENERATOR,
					       NULL, mgf);
		if (mg == NULL)
			goto out;
	}

	if (mgf_hash_algo != 0) {
		mghash = kmip_node_new_enumeration(
				KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM,
				NULL, mgf_hash_algo);
		if (mghash == NULL)
			goto out;
	}

	if (trailer_field != NULL) {
		trl = kmip_node_new_integer(KMIP_TAG_TRAILER_FIELD, NULL,
					    *trailer_field);
		if (trl == NULL)
			goto out;
	}

create:
	ret = kmip_node_new_structure_va(KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS,
					 NULL, 17, cmod, pad, hash, krl, sig,
					 algo, riv, iv, tag, ffl, ifl, cnt, icv,
					 salt, mg, mghash, trl);

out:
	kmip_node_free(cmod);
	kmip_node_free(pad);
	kmip_node_free(hash);
	kmip_node_free(krl);
	kmip_node_free(sig);
	kmip_node_free(algo);
	kmip_node_free(riv);
	kmip_node_free(iv);
	kmip_node_free(tag);
	kmip_node_free(ffl);
	kmip_node_free(ifl);
	kmip_node_free(cnt);
	kmip_node_free(icv);
	kmip_node_free(salt);
	kmip_node_free(mg);
	kmip_node_free(mghash);
	kmip_node_free(trl);

	return ret;
}

/**
 * Gets information from a Cryptographic Parameter attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Parameters                Structure     v1.0
 *     Block Cipher Mode           No        Enumeration   v1.0
 *     Padding Method              No        Enumeration   v1.0
 *     Hashing Algorithm           No        Enumeration   v1.0
 *     Key Role Type               No        Enumeration   v1.0
 *     Digital Signature Algorithm No        Enumeration   v1.2
 *     Cryptographic Algorithm     No        Enumeration   v1.2
 *     Random IV                   No        Boolean       v1.2
 *     IV Length                   No        Integer       v1.2
 *     Tag Length                  No        Integer       v1.2
 *     Fixed Field Length          No        Integer       v1.2
 *     Invocation Field Length     No        Integer       v1.2
 *     Counter Length              No        Integer       v1.2
 *     Initial Counter Value       No        Integer       v1.2
 *     Salt Length                 No        Integer       v1.4
 *     Mask Generator              No        Enumeration   v1.4
 *     Mask Generator Hashing Alg  No        Enumeration   v1.4
 *     P Source                    No        Byte String   v1.4
 *     Trailer Field               No        Integer       v1.4
 *
 * @param node              the KMIP node
 * @param mode              On return: the block cipher mode (0 if not avail,
 *                          can be NULL)
 * @param padding           On return: the padding method (0 if not avail,
 *                          can be NULL)
 * @param hash_algo         On return: the hashing algorithm (0 if not avail,
 *                          can be NULL)
 * @param key_role          On return: the key role type (0 if not avail,
 *                          can be NULL)
 * @param signature_algo    On return: the signature algorithm (0 if not avail,
 *                          can be NULL)
 * @param crypto_algo       On return: the cryptographic algorithm (0 if not
 *                          avail, can be NULL)
 * @param random_iv         On return: true if a random IV is used (false if
 *                          not avail, can be NULL)
 * @param iv_length         On return: the IV length (-1 if not avail, can be
 *                          NULL)
 * @param tag_length        On return: the tag length (-1 if not avail, can be
 *                          NULL)
 * @param fixed_field_length On return: the fixed field length (-1 if not avail,
 *                          can be NULL)
 * @param invoc_field_length On return: the invocation field length (-1 if not
 *                          avail, can be NULL)
 * @param counter_length    On return: the counter length (-1 if not avail,
 *                          can be NULL)
 * @param init_counter_value On return: the initial counter value (0 if not
 *                          avail, can be NULL)
 * @param salt_length       On return: the salt length (-1 if not avail,
 *                          can be NULL)
 * @param mgf               On return: the mask generator (0 if not avail,
 *                          can be NULL)
 * @param mgf_hash_algo     On return: the mask generator hash algorithm (0 if
 *                          not avail, can be NULL)
 * @param trailer_field     On return: the trailer field (0 if not avail,
 *                          can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_cryptographic_parameter(const struct kmip_node *node,
				     enum kmip_block_cipher_mode *mode,
				     enum kmip_padding_method *padding,
				     enum kmip_hashing_algo *hash_algo,
				     enum kmip_key_role_type *key_role,
				     enum kmip_signature_algo *signature_algo,
				     enum kmip_crypto_algo *crypto_algo,
				     bool *random_iv,
				     int32_t *iv_length,
				     int32_t *tag_length,
				     int32_t *fixed_field_length,
				     int32_t *invoc_field_length,
				     int32_t *counter_length,
				     int32_t *init_counter_value,
				     int32_t *salt_length,
				     enum kmip_mask_generator *mgf,
				     enum kmip_hashing_algo *mgf_hash_algo,
				     int32_t *trailer_field)
{
	struct kmip_node *n;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS)
		return -EBADMSG;

	if (mode != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_BLOCK_CIPHER_MODE, 0);
		*mode = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (padding != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_PADDING_METHOD, 0);
		*padding = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (hash_algo != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_HASHING_ALGORITHM, 0);
		*hash_algo = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (key_role != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_KEY_ROLE_TYPE, 0);
		*key_role = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (signature_algo != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
				KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM, 0);
		*signature_algo =
				(n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (crypto_algo != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, 0);
		*crypto_algo = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (random_iv != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_RANDOM_IV, 0);
		*random_iv = (n != NULL ? kmip_node_get_boolean(n) : false);
		kmip_node_free(n);
	}

	if (iv_length != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_IV_LENGTH, 0);
		*iv_length = (n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (tag_length != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_TAG_LENGTH, 0);
		*tag_length = (n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (fixed_field_length != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_FIXED_FIELD_LENGTH, 0);
		*fixed_field_length =
				(n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (invoc_field_length != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_INVOCATION_FIELD_LENGTH, 0);
		*invoc_field_length =
				(n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (counter_length != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_COUNTER_LENGTH, 0);
		*counter_length = (n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (init_counter_value != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_INITIAL_COUNTER_VALUE, 0);
		*init_counter_value =
				(n != NULL ? kmip_node_get_integer(n) : 0);
		kmip_node_free(n);
	}

	if (salt_length != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_SALT_LENGTH, 0);
		*salt_length = (n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (mgf != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_MASK_GENERATOR, 0);
		*mgf = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (mgf_hash_algo != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
				KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM, 0);
		*mgf_hash_algo = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (trailer_field != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_TRAILER_FIELD, 0);
		*trailer_field = (n != NULL ? kmip_node_get_integer(n) : 0);
		kmip_node_free(n);
	}

	return 0;
}

/**
 * Constructs a Cryptographic Domain Parameters attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Domain Params   Yes       Structure     v1.0
 *     Qlength                     No        Integer       v1.0
 *     Recommended Curve           No        Enumeration   v1.0
 *
 * @param qlength           the Q length (ignored of <= 0)
 * @param curve             the curve (ignored if 0)
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_cryptographic_domain_parameters(
					int32_t qlength,
					enum kmip_recommended_curve curve)
{
	struct kmip_node *ret = NULL, *qlen = NULL, *crv = NULL;

	if (qlength > 0) {
		qlen = kmip_node_new_integer(KMIP_TAG_Q_LENGTH, NULL, qlength);
		if (qlen == NULL)
			goto out;
	}

	if (curve != 0) {
		crv = kmip_node_new_enumeration(KMIP_TAG_RECOMMENDED_CURVE,
						NULL, curve);
		if (crv == NULL)
			goto out;
	}

	ret = kmip_node_new_structure_va(
			KMIP_TAG_CRYPTOGRAPHIC_DOMAIN_PARAMETERS, NULL, 2,
			qlen, crv);

out:
	kmip_node_free(qlen);
	kmip_node_free(crv);

	return ret;
}

/**
 * Gets the information from a Cryptographic Domain Parameters attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Cryptographic Domain Params   Yes       Structure     v1.0
 *     Qlength                     No        Integer       v1.0
 *     Recommended Curve           No        Enumeration   v1.0
 *
 * @param node              the KMIP node
 * @param qlength           On return: the Q length (-1 if not avail, can be
 *                          NULL)
 * @param curve             On return: the curve (0 if not avail, can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_cryptographic_domain_parameters(const struct kmip_node *node,
					     int32_t *qlength,
					     enum kmip_recommended_curve *curve)
{
	struct kmip_node *n;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_CRYPTOGRAPHIC_DOMAIN_PARAMETERS)
		return -EBADMSG;

	if (qlength != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_Q_LENGTH, 0);
		*qlength = (n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (curve != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_RECOMMENDED_CURVE, 0);
		*curve = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	return 0;
}

/**
 * Constructs a Digital Signature Algorithm attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Digital Signature Algorithm   Yes       Enumeration   v1.2
 *
 * @param signature_algo     the signature algorithm
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_digital_signature_algorithm(
				enum kmip_signature_algo signature_algo)
{
	return kmip_node_new_enumeration(KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM,
					 NULL, signature_algo);
}

/**
 * Gets the information from a Digital Signature Algorithm attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Digital Signature Algorithm   Yes       Enumeration   v1.2
 *
 * @param node              the KMIP node
 * @param signature_algo     the signature algorithm
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_digital_signature_algorithm(const struct kmip_node *node,
				enum kmip_signature_algo *signature_algo)
{
	if (node == NULL || signature_algo == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM)
		return -EBADMSG;

	*signature_algo = kmip_node_get_enumeration(node);
	return 0;
}

/**
 * Constructs a Object Group attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *     Object Group                Yes       Text String   v1.0
 *
 * @param group             the object group
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_object_group(const char *group)
{
	return kmip_node_new_text_string(KMIP_TAG_OBJECT_GROUP, NULL, group);
}

/**
 * Gets the information from a Object Group attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Object Group                  Yes       Text String   v1.0
 *
 * @param node              the KMIP node
 * @param group             the object group
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_object_group(const struct kmip_node *node, const char **group)
{
	if (node == NULL || group == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_OBJECT_GROUP)
		return -EBADMSG;

	*group = kmip_node_get_text_string(node);
	return 0;
}

/**
 * Constructs a Revocation Reason attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Revocation Reason             Yes       Structure     v1.0
 *     Revocation Reason Code      Yes       Enumeration   v1.0
 *     Revocation Message          No        Text String   v1.0
 *
 * @param reason            the revocation reason code
 * @param message           the revocation message (can be NULL)
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_revocation_reason(enum kmip_revoke_reason reason,
					     const char *message)
{
	struct kmip_node *ret = NULL, *rsn, *msg = NULL;

	rsn = kmip_node_new_enumeration(KMIP_TAG_REVOCATION_REASON_CODE, NULL,
					reason);
	if (rsn == NULL)
		goto out;
	if (message != NULL) {
		msg = kmip_node_new_text_string(KMIP_TAG_REVOCATION_MESSAGE,
						NULL, message);
		if (msg == NULL)
			goto out;
	}

	ret = kmip_node_new_structure_va(KMIP_TAG_REVOCATION_REASON, NULL, 2,
					 rsn, msg);

out:
	kmip_node_free(rsn);
	kmip_node_free(msg);

	return ret;
}

/**
 * Gets the information from a Revocation Reason attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Revocation Reason             Yes       Structure     v1.0
 *     Revocation Reason Code      Yes       Enumeration   v1.0
 *     Revocation Message          No        Text String   v1.0
 *
 * @param node              the KMIP node
 * @param reason            the revocation reason code
 * @param message           the revocation message (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_revocation_reason(const struct kmip_node *node,
			       enum kmip_revoke_reason *reason,
			       const char **message)
{
	struct kmip_node *n;

	if (node == NULL || reason == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_REVOCATION_REASON)
		return -EBADMSG;

	n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_REVOCATION_REASON_CODE, 0);
	if (n == NULL)
		return -EBADMSG;
	*reason = kmip_node_get_enumeration(n);
	kmip_node_free(n);

	if (message != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_REVOCATION_MESSAGE, 0);
		*message = (n != NULL ? kmip_node_get_text_string(n) : NULL);
		kmip_node_free(n);
	}

	return 0;
}

/**
 * Constructs a Contact Information attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *     Contact Information         Yes       Text String   v1.0
 *
 * @param contact           the contact information
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_contact_information(const char *contact)
{
	return kmip_node_new_text_string(KMIP_TAG_CONTACT_INFORMATION, NULL,
					 contact);
}

/**
 * Gets the information from a Contact Information attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Contact Information           Yes       Text String   v1.0
 *
 * @param node              the KMIP node
 * @param contact           the contact information
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_contact_information(const struct kmip_node *node,
					 const char **contact)
{
	if (node == NULL || contact == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_CONTACT_INFORMATION)
		return -EBADMSG;

	*contact = kmip_node_get_text_string(node);
	return 0;
}

/**
 * Constructs a Description attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *     Description                 Yes       Text String   v1.4
 *
 * @param description       the description
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_description(const char *description)
{
	return kmip_node_new_text_string(KMIP_TAG_DESCRIPTION, NULL,
					 description);
}

/**
 * Gets the information from a Description attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Description                   Yes       Text String   v1.4
 *
 * @param node              the KMIP node
 * @param description       the description
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_description(const struct kmip_node *node, const char **description)
{
	if (node == NULL || description == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_DESCRIPTION)
		return -EBADMSG;

	*description = kmip_node_get_text_string(node);
	return 0;
}

/**
 * Constructs a Comment attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *     Comment                     Yes       Text String   v1.4
 *
 * @param comment           the comment
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_comment(const char *comment)
{
	return kmip_node_new_text_string(KMIP_TAG_COMMENT, NULL, comment);
}

/**
 * Gets the information from a Comment attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Comment                       Yes       Text String   v1.4
 *
 * @param node              the KMIP node
 * @param comment           the comment
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_comment(const struct kmip_node *node, const char **comment)
{
	if (node == NULL || comment == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_COMMENT)
		return -EBADMSG;

	*comment = kmip_node_get_text_string(node);
	return 0;
}

/**
 * Constructs a Key Format Type attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Format Type               Yes       Enumeration   v2.0
 *
 * @param type              the key format type
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_key_format_type(enum kmip_key_format_type type)
{
	return kmip_node_new_enumeration(KMIP_TAG_KEY_FORMAT_TYPE, NULL, type);
}

/**
 * Gets the information from a Key Format Type attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Format Type               Yes       Enumeration   v2.0
 *
 * @param node              the KMIP node
 * @param type              the key format type
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_key_format_type(const struct kmip_node *node,
					  enum kmip_key_format_type *type)
{
	if (node == NULL || type == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_FORMAT_TYPE)
		return -EBADMSG;

	*type = kmip_node_get_enumeration(node);
	return 0;
}

/**
 * Constructs a Protection Level attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Level              Yes       Enumeration   v2.0
 *
 * @param level             the protection level
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_protection_level(enum kmip_protection_level level)
{
	return kmip_node_new_enumeration(KMIP_TAG_PROTECTION_LEVEL, NULL,
					 level);
}

/**
 * Gets the information from a Protection Level attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Level              Yes       Enumeration   v2.0
 *
 * @param node              the KMIP node
 * @param level             the protection level
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_protection_level(const struct kmip_node *node,
			      enum kmip_protection_level *level)
{
	if (node == NULL || level == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_PROTECTION_LEVEL)
		return -EBADMSG;

	*level = kmip_node_get_enumeration(node);
	return 0;
}

/**
 * Constructs a Protection Period attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Period             Yes       Interval      v2.0
 *
 * @param period            the protection period
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_protection_period(uint32_t period)
{
	return kmip_node_new_interval(KMIP_TAG_PROTECTION_PERIOD, NULL, period);
}

/**
 * Gets the information from a Protection Period attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Period             Yes       Interval      v2.0
 *
 * @param node              the KMIP node
 * @param period            the protection period
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_protection_period(const struct kmip_node *node, uint32_t *period)
{
	if (node == NULL || period == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_PROTECTION_PERIOD)
		return -EBADMSG;

	*period = kmip_node_get_interval(node);
	return 0;
}

/**
 * Constructs a Protection Storage Mask attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Storage Mask       Yes       Integer       v2.0
 *
 * @param protection_mask   the protection mask
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_protection_storage_mask(int32_t protection_mask)
{
	return kmip_node_new_integer(KMIP_TAG_PROTECTION_STORAGE_MASK, NULL,
				     protection_mask);
}

/**
 * Gets the information from a Protection Storage Mask attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Storage Mask       Yes       Integer       v2.0
 *
 * @param node              the KMIP node
 * @param protection_mask   the protection mask
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_protection_storage_mask(const struct kmip_node *node,
				     int32_t *protection_mask)
{
	if (node == NULL || protection_mask == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_PROTECTION_STORAGE_MASK)
		return -EBADMSG;

	*protection_mask = kmip_node_get_integer(node);
	return 0;
}

/**
 * Constructs a Fresh attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Fresh                         Yes       Boolean       v1.2
 *
 * @param fresh             the fresh value
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_fresh(bool fresh)
{
	return kmip_node_new_boolean(KMIP_TAG_FRESH, NULL, fresh);
}

/**
 * Gets the information from a Fresh attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Fresh                         Yes       Boolean       v1.2
 *
 * @param node              the KMIP node
 * @param fresh             the fresh value
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_fresh(const struct kmip_node *node, bool *fresh)
{
	if (node == NULL || fresh == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_FRESH)
		return -EBADMSG;

	*fresh = kmip_node_get_boolean(node);
	return 0;
}

/**
 * Constructs a Key Value Present attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Value Present             Yes       Boolean       v1.2
 *
 * @param present           the present value
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_key_value_present(bool present)
{
	return kmip_node_new_boolean(KMIP_TAG_KEY_VALUE_PRESENT, NULL, present);
}

/**
 * Gets the information from a Key Value Present attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Value Present             Yes       Boolean       v1.2
 *
 * @param node              the KMIP node
 * @param present           the present value
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_key_value_present(const struct kmip_node *node, bool *present)
{
	if (node == NULL || present == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_VALUE_PRESENT)
		return -EBADMSG;

	*present = kmip_node_get_boolean(node);
	return 0;
}

/**
 * Constructs a Short Unique Identifier attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Short Unique Identifier       Yes       Byte String   v2.0
 *
 * @param short_uid         the short unique identifier
 * @param short_uid_len     the length of the short unique identifier
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_short_unique_identifier(
				const unsigned char *short_uid,
				uint32_t short_uid_len)
{
	return kmip_node_new_byte_string(KMIP_TAG_SHORT_UNIQUE_IDENTIFIER, NULL,
					 short_uid, short_uid_len);
}

/**
 * Gets the information from a Short Unique Identifier attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Short Unique Identifier       Yes       Byte String   v2.0
 *
 * @param node              the KMIP node
 * @param short_uid         the short unique identifier
 * @param short_uid_len     the length of the short unique identifier
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_short_unique_identifier(const struct kmip_node *node,
				     const unsigned char **short_uid,
				     uint32_t *short_uid_len)
{
	if (node == NULL || short_uid == NULL || short_uid_len == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_SHORT_UNIQUE_IDENTIFIER)
		return -EBADMSG;

	*short_uid = kmip_node_get_byte_string(node, short_uid_len);
	return 0;
}

/**
 * Constructs a Application Specific Information attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Application Specific Info.    Yes       Structure     v1.0
 *     Application Namespace       Yes       Text String   v1.0
 *     Application Data            Yes/No    Text String   v1.0
 *
 * @param name_space        the application namespace
 * @param data              the application data
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_application_specific_information(
				const char *name_space, const char *data)
{
	struct kmip_node *ret = NULL, *ns, *d = NULL;

	if (name_space == NULL)
		return NULL;

	ns = kmip_node_new_text_string(KMIP_TAG_APPLICATION_NAMESPACE, NULL,
				       name_space);
	if (ns == NULL)
		goto out;
	if (data != NULL) {
		d = kmip_node_new_text_string(KMIP_TAG_APPLICATION_DATA, NULL,
					      data);
		if (d == NULL)
			goto out;
	}

	ret = kmip_node_new_structure_va(KMIP_TAG_APPLICATION_DATA, NULL, 2,
					 ns, d);

out:
	kmip_node_free(ns);
	kmip_node_free(d);

	return ret;
}

/**
 * Gets the information from a Application Specific Information attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Application Specific Info.    Yes       Structure     v1.0
 *     Application Namespace       Yes       Text String   v1.0
 *     Application Data            Yes/No    Text String   v1.0
 *
 * @param node              the KMIP node
 * @param name_space        the application namespace
 * @param data              the application data (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_application_specific_information(const struct kmip_node *node,
					      const char **name_space,
					      const char **data)
{
	struct kmip_node *n;

	if (node == NULL || name_space == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_APPLICATION_DATA)
		return -EBADMSG;

	n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_APPLICATION_NAMESPACE, 0);
	if (n == NULL)
		return -EBADMSG;
	*name_space = kmip_node_get_text_string(n);
	kmip_node_free(n);

	if (data != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_APPLICATION_DATA, 0);
		if (n == NULL)
			return -EBADMSG;
		*data = kmip_node_get_text_string(n);
		kmip_node_free(n);
	}

	return 0;
}

/**
 * Constructs a Key Value Location attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Value Location            Yes       Structure     v1.2
 *     Key Value Location Value    Yes       Text String   v1.2
 *     Key Value Location Type     Yes       Enumeration   v1.2
 *
 * @param value             the value of the key value location
 * @param type              the type of the key value location
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_key_value_location(const char *value,
					enum kmip_key_value_location_type type)
{
	struct kmip_node *name = NULL, *val, *typ;

	if (value == NULL)
		return NULL;

	val = kmip_node_new_text_string(KMIP_TAG_KEY_VALUE_LOCATION_VALUE, NULL,
					value);
	typ = kmip_node_new_enumeration(KMIP_TAG_KEY_VALUE_LOCATION_TYPE, NULL,
					type);
	if (val == NULL || typ == NULL)
		goto out;

	name = kmip_node_new_structure_va(KMIP_TAG_KEY_VALUE_LOCATION, NULL, 2,
					  val, typ);

out:
	kmip_node_free(val);
	kmip_node_free(typ);

	return name;
}

/**
 * Gets the information from a Key Value Location attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Value Location            Yes       Structure     v1.2
 *     Key Value Location Value    Yes       Text String   v1.2
 *     Key Value Location Type     Yes       Enumeration   v1.2
 *
 * @param node              the KMIP node
 * @param value             the value of the key value location
 * @param type              the type of the key value location
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_key_value_location(const struct kmip_node *node,
		const char **value, enum kmip_key_value_location_type *type)
{
	struct kmip_node *val, *typ;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_VALUE_LOCATION)
		return -EBADMSG;

	val = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_KEY_VALUE_LOCATION_VALUE, 0);
	typ = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_KEY_VALUE_LOCATION_TYPE, 0);
	if (val == NULL || typ == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	if (value != NULL)
		*value = kmip_node_get_text_string(val);
	if (type != NULL)
		*type = kmip_node_get_enumeration(typ);

out:
	kmip_node_free(val);
	kmip_node_free(typ);

	return rc;
}

/**
 * Constructs a Digest attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Digest                        Yes       Structure     v1.0
 *     Hashing Algorithm           Yes       Enumeration   v1.0
 *     Digest Value                Yes       Byte String   v1.0
 *
 * @param hash_algo         the hashing algorithm
 * @param digest            the digest value
 * @param digest_len        the digest length
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_digest(enum kmip_hashing_algo hash_algo,
				  const unsigned char *digest,
				  uint32_t digest_len)
{
	struct kmip_node *ret = NULL, *algo, *val;

	if (digest == NULL || digest_len == 0)
		return NULL;

	algo = kmip_node_new_enumeration(KMIP_TAG_HASHING_ALGORITHM, NULL,
					 hash_algo);
	val = kmip_node_new_byte_string(KMIP_TAG_DIGEST_VALUE, NULL,
					digest, digest_len);
	if (algo == NULL || val == NULL)
		goto out;

	ret = kmip_node_new_structure_va(KMIP_TAG_DIGEST, NULL, 2, algo, val);

out:
	kmip_node_free(algo);
	kmip_node_free(val);

	return ret;
}

/**
 * Gets the information from a Digest attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Digest                        Yes       Structure     v1.0
 *     Hashing Algorithm           Yes       Enumeration   v1.0
 *     Digest Value                Yes       Byte String   v1.0
 *
 * @param node              the KMIP node
 * @param hash_algo         the hashing algorithm (can be NULL)
 * @param digest            the digest value (can be NULL)
 * @param digest_len        the digest length (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_digest(const struct kmip_node *node,
		    enum kmip_hashing_algo *hash_algo,
		    const unsigned char **digest, uint32_t *digest_len)
{
	struct kmip_node *algo, *val;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_DIGEST)
		return -EBADMSG;

	algo = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_HASHING_ALGORITHM, 0);
	val = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_DIGEST_VALUE, 0);
	if (algo == NULL || val == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	if (hash_algo != NULL)
		*hash_algo = kmip_node_get_enumeration(algo);
	if (digest != NULL)
		*digest = kmip_node_get_byte_string(val, digest_len);

out:
	kmip_node_free(algo);
	kmip_node_free(val);

	return rc;
}

/**
 * Constructs a Sensitive attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Sensitive                     Yes       Boolean       v1.4
 *
 * @param sensitive         the sensitive value
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_sensitive(bool sensitive)
{
	return kmip_node_new_boolean(KMIP_TAG_SENSITIVE, NULL, sensitive);
}

/**
 * Gets the information from a Sensitive attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Sensitive                     Yes       Boolean       v1.4
 *
 * @param node              the KMIP node
 * @param sensitive         the sensitive value
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_sensitive(const struct kmip_node *node, bool *sensitive)
{
	if (node == NULL || sensitive == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_SENSITIVE)
		return -EBADMSG;

	*sensitive = kmip_node_get_boolean(node);
	return 0;
}

/**
 * Constructs a Always Sensitive attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Always Sensitive              Yes       Boolean       v1.4
 *
 * @param sensitive         the sensitive value
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_always_sensitive(bool sensitive)
{
	return kmip_node_new_boolean(KMIP_TAG_ALWAYS_SENSITIVE, NULL,
				     sensitive);
}

/**
 * Gets the information from a Always Sensitive attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Always Sensitive              Yes       Boolean       v1.4
 *
 * @param node              the KMIP node
 * @param sensitive         the sensitive value
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_always_sensitive(const struct kmip_node *node, bool *sensitive)
{
	if (node == NULL || sensitive == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_ALWAYS_SENSITIVE)
		return -EBADMSG;

	*sensitive = kmip_node_get_boolean(node);
	return 0;
}

/**
 * Constructs a Extractable attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Extractable                   Yes       Boolean       v1.4
 *
 * @param extractable       the extractable value
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_extractable(bool extractable)
{
	return kmip_node_new_boolean(KMIP_TAG_EXTRACTABLE, NULL, extractable);
}

/**
 * Gets the information from a Extractable attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Extractable                   Yes       Boolean       v1.4
 *
 * @param node              the KMIP node
 * @param extractable       the extractable value
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_extractable(const struct kmip_node *node, bool *extractable)
{
	if (node == NULL || extractable == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_EXTRACTABLE)
		return -EBADMSG;

	*extractable = kmip_node_get_boolean(node);
	return 0;
}

/**
 * Constructs a Never Extractable attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Never Extractable             Yes       Boolean       v1.4
 *
 * @param extractable       the extractable value
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_never_extractable(bool extractable)
{
	return kmip_node_new_boolean(KMIP_TAG_NEVER_EXTRACTABLE, NULL,
				     extractable);
}

/**
 * Gets the information from a Never Extractable attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Never Extractable             Yes       Boolean       v1.4
 *
 * @param node              the KMIP node
 * @param extractable       the extractable value
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_never_extractable(const struct kmip_node *node, bool *extractable)
{
	if (node == NULL || extractable == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_NEVER_EXTRACTABLE)
		return -EBADMSG;

	*extractable = kmip_node_get_boolean(node);
	return 0;
}

/**
 * Constructs a Link attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Link                          Yes       Structure     v1.0
 *     Link Type                   Yes       Enumeration   v1.0
 *     Linked Object Identifier    Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param type              the link type
 * @param obj_id            the linked object identifier
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_link(enum kmip_link_type type,
				struct kmip_node *obj_id)
{
	struct kmip_node *ret = NULL, *typ;

	if (obj_id == NULL)
		return NULL;

	typ = kmip_node_new_enumeration(KMIP_TAG_LINK_TYPE, NULL,
					type);
	if (typ == NULL)
		return NULL;

	ret = kmip_node_new_structure_va(KMIP_TAG_LINK, NULL, 2,
					 typ, obj_id);
	kmip_node_free(typ);

	return ret;
}

/**
 * Gets the information from a Link attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Link                          Yes       Structure     v1.0
 *     Link Type                   Yes       Enumeration   v1.0
 *     Linked Object Identifier    Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0

 *
 * @param node              the KMIP node
 * @param type              the link type
 * @param obj_id            the linked object identifier
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_link(const struct kmip_node *node, enum kmip_link_type *type,
		  struct kmip_node **obj_id)
{
	struct kmip_node *n;

	if (type == NULL || obj_id == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_LINK)
		return -EBADMSG;

	n = kmip_node_get_structure_element_by_tag(node, KMIP_TAG_LINK_TYPE, 0);
	if (n == NULL)
		return -EBADMSG;
	*type = kmip_node_get_enumeration(n);
	kmip_node_free(n);

	*obj_id = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_LINKED_OBJECT_IDENTIFIER, 0);
	if (*obj_id == NULL)
		return -EBADMSG;

	return 0;
}

/**
 * Constructs a Linked Object Identifier attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Linked Object Identifier      Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param text_id           the linked identifier as text string (or NULL)
 * @param enum_id           the linked identifier as enumeration (or 0)
 * @param int_id            the linked identifier as integer
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_linked_object_identifier(const char *text_id,
					enum kmip_unique_identifier enum_id,
					int32_t int_id)
{
	if (text_id != NULL && enum_id != 0)
		return NULL;

	if (text_id != NULL)
		return kmip_node_new_text_string(
			KMIP_TAG_LINKED_OBJECT_IDENTIFIER, NULL, text_id);
	if (enum_id != 0)
		return kmip_node_new_enumeration(
			KMIP_TAG_LINKED_OBJECT_IDENTIFIER, NULL, enum_id);

	return kmip_node_new_integer(KMIP_TAG_LINKED_OBJECT_IDENTIFIER, NULL,
				     int_id);
}

/**
 * Gets the information from a Linked Object Identifier attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Linked Object Identifier      Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param text_id           the linked identifier as text string (can be NULL)
 * @param enum_id           the linked identifier as enumeration (can be NULL)
 * @param int_id            the linked identifier as integer (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_linked_object_identifier(const struct kmip_node *node,
				      const char **text_id,
				      enum kmip_unique_identifier *enum_id,
				      int32_t *int_id)
{
	if (node == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_LINKED_OBJECT_IDENTIFIER)
		return -EBADMSG;

	if (text_id != NULL) {
		if (kmip_node_get_type(node) == KMIP_TYPE_TEXT_STRING)
			*text_id = kmip_node_get_text_string(node);
		else
			*text_id = NULL;
	}

	if (enum_id != NULL) {
		if (kmip_node_get_type(node) == KMIP_TYPE_ENUMERATION)
			*enum_id = kmip_node_get_enumeration(node);
		else
			*enum_id = 0;
	}

	if (int_id != NULL) {
		if (kmip_node_get_type(node) == KMIP_TYPE_INTEGER)
			*int_id = kmip_node_get_integer(node);
		else
			*int_id = 0;
	}

	return 0;
}

/**
 * Constructs a Operation Policy Name attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *     Operation Policy Name       Yes       Text String   v1.x only
 *
 * @param policy            the policy name
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_operation_policy_name(const char *policy)
{
	return kmip_node_new_text_string(KMIP_TAG_OPERATION_POLICY_NAME, NULL,
					 policy);
}

/**
 * Gets the information from a Operation Policy Name attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Operation Policy Name         Yes       Text String   v1.x only
 *
 * @param node              the KMIP node
 * @param policy            the policy name
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_operation_policy_name(const struct kmip_node *node,
				   const char **policy)
{
	if (node == NULL || policy == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_OPERATION_POLICY_NAME)
		return -EBADMSG;

	*policy = kmip_node_get_text_string(node);
	return 0;
}

/**
 * Constructs a Lease Time attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Lease Time                    Yes       Interval      v1.0
 *
 * @param lease_time        the lease time
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_lease_time(uint32_t lease_time)
{
	return kmip_node_new_interval(KMIP_TAG_LEASE_TIME, NULL, lease_time);
}

/**
 * Gets the information from a Lease Time attribute node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Lease Time                    Yes       Interval      v1.0
 *
 * @param node              the KMIP node
 * @param lease_time        the lease time
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_lease_time(const struct kmip_node *node, uint32_t *lease_time)
{
	if (node == NULL || lease_time == NULL)
		return -EBADMSG;

	if (kmip_node_get_tag(node) != KMIP_TAG_LEASE_TIME)
		return -EBADMSG;

	*lease_time = kmip_node_get_interval(node);
	return 0;
}

