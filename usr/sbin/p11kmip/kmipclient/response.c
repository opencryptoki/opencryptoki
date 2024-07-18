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

#include "kmip.h"

/**
 * Gets the version information from a Protocol Version node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protocol Version                        Structure     v1.0
 *     Protocol Version Major      Yes       Integer       v1.0
 *     Protocol Version Minor      Yes       Integer       v1.0
 *
 * @param node              the KMIP node
 * @param version           On return: the protocol version
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_protocol_version(const struct kmip_node *node,
			      struct kmip_version *version)
{
	struct kmip_node *maj, *min;
	int rc = 0;

	if (node == NULL || version == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_PROTOCOL_VERSION)
		return -EBADMSG;

	maj = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_PROTOCOL_VERSION_MAJOR, 0);
	min = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_PROTOCOL_VERSION_MINOR, 0);
	if (maj == NULL || min == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	version->major = kmip_node_get_integer(maj);
	version->minor = kmip_node_get_integer(min);

out:
	kmip_node_free(maj);
	kmip_node_free(min);

	return rc;
}

/**
 * Gets the version information from a Profile Version node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Profile Version                         Structure     v1.0
 *     Profile Version Major       Yes       Integer       v1.0
 *     Profile Version Minor       Yes       Integer       v1.0
 *
 * @param node              the KMIP node
 * @param version           On return: the profile version
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_profile_version(const struct kmip_node *node,
			     struct kmip_version *version)
{
	struct kmip_node *maj, *min;
	int rc = 0;

	if (node == NULL || version == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_PROFILE_VERSION)
		return -EBADMSG;

	maj = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_PROFILE_VERSION_MAJOR, 0);
	min = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_PROFILE_VERSION_MINOR, 0);
	if (maj == NULL || min == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	version->major = kmip_node_get_integer(maj);
	version->minor = kmip_node_get_integer(min);

out:
	kmip_node_free(maj);
	kmip_node_free(min);

	return rc;
}

/**
 * Gets information from a Response Header node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Response Header               Yes       Structure     v1.0
 *     Protocol Version            Yes       Structure     v1.0
 *     Time Stamp                  No        Date Time     v1.0
 *     Nonce                       No        Structure     v1.2
 *     Server Hashed Password      No        Byte String   v2.0
 *     Attestation Type            No        Enumeration   v1.2
 *        ... may be repeated
 *     Client Correlation Value    No        Text String   v1.4
 *     Server Correlation Value    No        Text String   v1.4
 *     Batch Count                 Yes       Integer       v1.0
 *
 * @param node              the KMIP node
 * @param version           the protocol version (can be NULL)
 * @param time_stamp        the time stamp (can be NULL)
 * @param client_corr_value the client correlation value. Can be NULL.
 * @param server_corr_value the server correlation value. Can be NULL.
 * @param batch_count       the batch count (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned node is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_response_header(const struct kmip_node *node,
			     struct kmip_version *version,
			     int64_t *time_stamp,
			     const char **client_corr_value,
			     const char **server_corr_value,
			     int32_t *batch_count)
{
	struct kmip_node *n;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_HEADER)
		return -EBADMSG;

	if (time_stamp != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_TIME_STAMP, 0);
		if (n == NULL)
			return -EBADMSG;
		*time_stamp = kmip_node_get_date_time(n);
		kmip_node_free(n);
	}

	if (batch_count != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_BATCH_COUNT, 0);
		if (n == NULL)
			return -EBADMSG;
		*batch_count = kmip_node_get_integer(n);
		kmip_node_free(n);
	}

	if (version != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_PROTOCOL_VERSION, 0);
		if (n == NULL)
			return -EBADMSG;
		rc = kmip_get_protocol_version(n, version);
		kmip_node_free(n);
		if (rc != 0)
			return rc;
	}

	if (client_corr_value != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_CLIENT_CORRELATION_VALUE, 0);
		if (n == NULL)
			return -EBADMSG;
		*client_corr_value = kmip_node_get_text_string(n);
		kmip_node_free(n);
	}

	if (server_corr_value != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_SERVER_CORRELATION_VALUE, 0);
		if (n == NULL)
			return -EBADMSG;
		*server_corr_value = kmip_node_get_text_string(n);
		kmip_node_free(n);
	}

	return 0;
}

/**
 * Gets information from a Response Batch Item node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Batch Item                    Yes       Structure     v1.0
 *     Operation                   Yes       Enumeration   v1.0
 *     Unique Batch Item ID        No        Byte String   v1.0
 *     Result Status               Yes       Enumeration   v1.0
 *     Result Reason               No/Yes    Enumeration   v1.0
 *     Result Message              No/Yes    Text String   v1.0
 *     Asynchronous Correl. Value  No/Yes    Byte String   v1.0
 *     Response Payload            Yes       Structure     v1.0
 *     Message Extension           No        Structure     v1.0
 *
 * @param node              the KMIP node
 * @param operation         the operation (can be NULL)
 * @param batch_id          the batch ID (can be NULL)
 * @param batch_id_length   the batch ID length (can be NULL)
 * @param status            the result status (can be NULL)
 * @param reason            the result reason (can be NULL)
 * @param message           the result message (can be NULL)
 * @param async_corr_value  the asynchronous correlation value (can be NULL)
 * @param async_corr_value_len the length if the async corr. value (can be NULL)
 * @param payload           the response payload (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned node is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_response_batch_item(const struct kmip_node *node,
				 enum kmip_operation *operation,
				 const unsigned char **batch_id,
				 uint32_t *batch_id_length,
				 enum kmip_result_status *status,
				 enum kmip_result_reason *reason,
				 const char **message,
				 const unsigned char **async_corr_value,
				 uint32_t *async_corr_value_len,
				 struct kmip_node **payload)
{
	struct kmip_node *n;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_BATCH_ITEM)
		return -EBADMSG;

	if (operation != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_OPERATION, 0);
		if (n == NULL)
			return -EBADMSG;
		*operation = kmip_node_get_enumeration(n);
		kmip_node_free(n);
	}

	if (batch_id != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_UNIQUE_BATCH_ITEM_ID, 0);
		if (n == NULL) {
			*batch_id = NULL;
			if (batch_id_length != NULL)
				*batch_id_length = 0;
		} else {
			*batch_id = kmip_node_get_byte_string(n,
							      batch_id_length);
			kmip_node_free(n);
		}
	}

	if (status != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_RESULT_STATUS, 0);
		if (n == NULL)
			return -EBADMSG;
		*status = kmip_node_get_enumeration(n);
		kmip_node_free(n);
	}

	if (reason != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_RESULT_REASON, 0);
		*reason = (n == NULL ? 0 : kmip_node_get_enumeration(n));
		kmip_node_free(n);
	}

	if (message != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_RESULT_MESSAGE, 0);
		*message = (n == NULL ? NULL :
					kmip_node_get_text_string(n));
		kmip_node_free(n);
	}

	if (async_corr_value != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE,
					0);
		if (n != NULL) {
			*async_corr_value = kmip_node_get_byte_string(n,
							async_corr_value_len);
		} else {
			*async_corr_value = NULL;
			if (async_corr_value_len != NULL)
				*async_corr_value_len = 0;
		}
		kmip_node_free(n);
	}

	if (payload != NULL)
		*payload = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_RESPONSE_PAYLOAD, 0);

	return 0;
}

/**
 * Gets information from a Response Message node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Response Message              Yes       Structure     v1.0
 *     Response Header             Yes       Structure     v1.0
 *     Batch Item                  Yes       Structure     v1.0
 *     ... may be repeated
 *
 * @param node              the KMIP node
 * @param response_header   the response header (can be NULL)
 * @param batch_index       the index of the response batch item to return
 * @param batch_item        the batch item (can be NULL)

 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_response(const struct kmip_node *node,
		      struct kmip_node **response_header,
		      unsigned int batch_index,
		      struct kmip_node **batch_item)
{
	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_MESSAGE)
		return -EBADMSG;

	if (response_header != NULL) {
		*response_header = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_RESPONSE_HEADER, 0);
		if (*response_header == NULL)
			return -EBADMSG;
	}

	if (batch_item != NULL)
		*batch_item = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_BATCH_ITEM,
						batch_index);

	return 0;
}

struct kmip_query_info {
	enum kmip_query_function query_function;
	enum kmip_tag result_tag;

};

static const struct kmip_query_info query_info[] = {
	{ .query_function = KMIP_QUERY_OPERATIONS,
			.result_tag = KMIP_TAG_OPERATION, },
	{ .query_function = KMIP_QUERY_OBJECTS,
			.result_tag = KMIP_TAG_OBJECT_TYPE, },
	{ .query_function = KMIP_QUERY_SERVER_INFORMATION,
			.result_tag = KMIP_TAG_VENDOR_IDENTIFICATION, },
	{ .query_function = KMIP_QUERY_SERVER_INFORMATION,
			.result_tag = KMIP_TAG_SERVER_INFORMATION, },
	{ .query_function = KMIP_QUERY_APPLICATION_NAMESPACES,
			.result_tag = KMIP_TAG_APPLICATION_NAMESPACE, },
	{ .query_function = KMIP_QUERY_EXTENSION_LIST,
			.result_tag = KMIP_TAG_EXTENSION_INFORMATION, },
	{ .query_function = KMIP_QUERY_EXTENSION_MAP,
			.result_tag = KMIP_TAG_EXTENSION_INFORMATION, },
	{ .query_function = KMIP_QUERY_ATTESTATION_TYPES,
			.result_tag = KMIP_TAG_ATTESTATION_TYPE, },
	{ .query_function = KMIP_QUERY_QUERY_RNGS,
			.result_tag = KMIP_TAG_RNG_PARAMETERS, },
	{ .query_function = KMIP_QUERY_VALIDATIONS,
			.result_tag = KMIP_TAG_VALIDATION_INFORMATION, },
	{ .query_function = KMIP_QUERY_PROFILES,
			.result_tag = KMIP_TAG_PROFILE_INFORMATION, },
	{ .query_function = KMIP_QUERY_CAPABILITIES,
			.result_tag = KMIP_TAG_CAPABILITY_INFORMATION, },
	{ .query_function = KMIP_QUERY_CLIENT_REGISTRATION_METHODS,
			.result_tag = KMIP_TAG_CLIENT_REGISTRATION_METHOD, },
	{ .query_function = KMIP_QUERY_DEFAULTS_INFORMATION,
			.result_tag = KMIP_TAG_DEFAULTS_INFORMATION, },
	{ .query_function = KMIP_QUERY_STORAGE_PROTECTION_MASKS,
			.result_tag = KMIP_TAG_PROTECTION_STORAGE_MASKS, },
	{ .query_function = 0, .result_tag = 0, },
};

/**
 * Gets information from a Query response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Operation                   No        Enumeration   v1.0
 *        ... may be repeated
 *     Object Type                 No        Enumeration   v1.0
 *        ... may be repeated
 *     Vendor Identification       No        Text String   v1.0
 *     Server Information          No        Structure     v1.0
 *     Application Namespace       No        Text String   v1.0
 *        ... may be repeated
 *     Extension Information       No        Structure     v1.2
 *        ... may be repeated
 *     Attestation Type            No        Enumeration   v1.2
 *        ... may be repeated
 *     RNG Parameters              No        Structure     v1.3
 *        ... may be repeated
 *     Profile Information         No        Structure     v1.3
 *        ... may be repeated
 *     Validation Information      No        Structure     v1.3
 *        ... may be repeated
 *     Capability Information      No        Structure     v1.3
 *        ... may be repeated
 *     Client Registration Method  No        Enumeration   v1.3
 *        ... may be repeated
 *     Defaults Information        No        Structure     v2.0
 *     Protection Storage Masks    No        Structure     v2.0
 *
 * @param node              the KMIP node
 * @param query_function    the query function to get the results for
 * @param num_results       On return: the number of result items of the
 *                          specified query function (can be NULL).
 * @param result_index      the index of the query result item to return
 * @param result            On return: the query result item of the specified
 *                          query function and index. Function returns -ENOENT
 *                          if no result is available. Can be NULL.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned node is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_query_response_payload(const struct kmip_node *node,
				    enum kmip_query_function query_function,
				    unsigned int *num_results,
				    unsigned int result_index,
				    struct kmip_node **result)
{
	enum kmip_tag result_tag = 0;
	unsigned int i;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	for (i = 0; query_info[i].query_function != 0; i++) {
		if (query_info[i].query_function == query_function) {
			result_tag = query_info[i].result_tag;
			break;
		}
	}
	if (result_tag == 0)
		return -EBADMSG;

	if (num_results != NULL) {
		*num_results = kmip_node_get_structure_element_by_tag_count(
							node, result_tag);

		/*
		 * KMIP_QUERY_SERVER_INFORMATION may return 2 different result
		 * tags, count both of them.
		 */
		if (query_function == KMIP_QUERY_SERVER_INFORMATION) {
			*num_results +=
				kmip_node_get_structure_element_by_tag_count(
					node, KMIP_TAG_SERVER_INFORMATION);
		}
	}

	if (result == NULL)
		return 0;

	*result = kmip_node_get_structure_element_by_tag(node, result_tag,
							 result_index);
	if (*result == NULL) {
		/*
		 * KMIP_QUERY_SERVER_INFORMATION may return 2 different result
		 * tags, return both of them.
		 */
		if (query_function == KMIP_QUERY_SERVER_INFORMATION) {
			if (result_index > 0)
				result_index -= 1;
			*result = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_SERVER_INFORMATION,
						result_index);
			if (*result != NULL)
				return 0;
		}

		return -ENOENT;
	}

	return 0;
}

/**
 * Gets information from a Discover Versions response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Protocol Version            No        Structure     v1.2
 *        ... may be repeated
 *
 * @param node              the KMIP node
 * @param num_versions      On return: the number of versions (can be NULL)
 * @param index             the index of the version item to return
 * @param version           On return: the version item of the specified
 *                          index. Function returns -ENOENT if no version is
 *                          available at that index. (can be NULL).
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
int kmip_get_discover_versions_response_payload(const struct kmip_node *node,
						unsigned int *num_versions,
						unsigned int index,
						struct kmip_version *version)
{
	struct kmip_node *n;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (num_versions != NULL)
		*num_versions = kmip_node_get_structure_element_count(node);

	if (version == NULL)
		return 0;

	n = kmip_node_get_structure_element_by_index(node, index);
	if (n == NULL)
		return -ENOENT;
	rc = kmip_get_protocol_version(n, version);
	kmip_node_free(n);

	return rc;
}

/**
 * Gets information from a Create response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Object Type                 Yes       Enumeration   v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Template-Attribute          No        Structure     v1.x only
 *
 *
 * @param node              the KMIP node
 * @param obj_type          the object type of the created object (can be NULL)
 * @param unique_id         the unique id node (can be NULL)
 * @param num_attrs         On return: the number of attributes (can be NULL).
 * @param attr_index        the index of the attribute to get
 * @param attributes        the attribute (implicitly set by the server) at the
 *                          specified index (as v2.x attributes) (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_create_response_payload(const struct kmip_node *node,
				     enum kmip_object_type *obj_type,
				     struct kmip_node **unique_id,
				     unsigned int *num_attrs,
				     unsigned int attr_index,
				     struct kmip_node **attribute)
{
	struct kmip_node *n;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (obj_type != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
							   KMIP_TAG_OBJECT_TYPE,
							   0);
		if (n == NULL)
			return -EBADMSG;
		*obj_type = kmip_node_get_enumeration(n);
		kmip_node_free(n);
	}

	if (unique_id != NULL)
		*unique_id = kmip_node_get_structure_element_by_tag(
					node, KMIP_TAG_UNIQUE_IDENTIFIER, 0);

	if (attribute == NULL && num_attrs == NULL)
		return 0;

	n = kmip_node_get_structure_element_by_tag(node,
						   KMIP_TAG_TEMPLATE_ATTRIBUTE,
						   0);
	if (n == NULL) {
		if (num_attrs != NULL)
			*num_attrs = 0;

		if (attribute == NULL)
			return 0;

		rc = -ENOENT;
		goto error;
	}

	rc = kmip_get_attributes(n, num_attrs, attr_index, attribute);
	kmip_node_free(n);
	if (rc != 0)
		goto error;

	return 0;

error:
	if (unique_id != NULL) {
		kmip_node_free(*unique_id);
		*unique_id = NULL;
	}
	return rc;
}

/**
 * Gets information from a Get Attribute List response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute Name              Yes       Text String   v1.x only
 *     ... may be repeated
 *     Attribute Reference         Yes       Enumeration   v2.x only
 *                                           Structure     v2.x only
 *     ... may be repeated
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 * @param num_attr_refs     On return: the number of attribute references
 *                          (can be NULL).
 * @param index             the index of the attribute reference to get
 * @param attr_ref          the attribute (as v2.x attribute reference) at the
 *                          specified index. Function returns -ENOENT if no
 *                          attribute is available at the index.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_get_attribute_list_response_payload(const struct kmip_node *node,
						 struct kmip_node **unique_id,
						 unsigned int *num_attr_refs,
						 unsigned int index,
						 struct kmip_node **attr_ref)
{
	struct kmip_node *n;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (unique_id != NULL)
		*unique_id = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_UNIQUE_IDENTIFIER, 0);

	if (num_attr_refs != NULL)
		*num_attr_refs =
			kmip_node_get_structure_element_count(node) - 1;

	if (attr_ref == NULL)
		return 0;

	n = kmip_node_get_structure_element_by_index(node, index + 1);
	if (n == NULL) {
		if (unique_id != NULL) {
			kmip_node_free(*unique_id);
			*unique_id = NULL;
		}
		return -ENOENT;
	}

	if (kmip_node_get_tag(n) == KMIP_TAG_ATTRIBUTE_REFERENCE) {
		/* Its already a KMIP v2.x attribute reference */
		*attr_ref = n;
		return 0;
	}

	/* Must be a KMIP v1.x attribute name then */
	rc = kmip_get_attribute_name_v1(n, attr_ref);
	kmip_node_free(n);
	if (rc != 0) {
		if (unique_id != NULL) {
			kmip_node_free(*unique_id);
			*unique_id = NULL;
		}
		return rc;
	}

	return 0;
}

/**
 * Gets information from a Get Attributes response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute                   No        Structure     v1.x only
 *     ... may be repeated
 *     Attributes                  Yes       Structure     v2.x only
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 * @param num_attrs         On return: the number of attributes (can be NULL).
 * @param index             the index of the attribute to get
 * @param v2_attr           the attribute (as v2.x attribute) at the
 *                          specified index. Function returns -ENOENT if no
 *                          attribute is available at the index.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_get_attributes_response_payload(const struct kmip_node *node,
					     struct kmip_node **unique_id,
					     unsigned int *num_attrs,
					     unsigned int index,
					     struct kmip_node **v2_attr)
{
	struct kmip_node *attr;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (unique_id != NULL)
		*unique_id = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_UNIQUE_IDENTIFIER, 0);

	if (v2_attr == NULL && num_attrs == NULL)
		return 0;

	attr = kmip_node_get_structure_element_by_index(node, 1);
	if (attr == NULL) {
		if (num_attrs != NULL)
			*num_attrs = 0;

		if (v2_attr == NULL)
			return 0;

		rc = -ENOENT;
		goto error;
	}

	if (kmip_node_get_tag(attr) == KMIP_TAG_ATTRIBUTES) {
		/* Its already a KMIP v2.x attributes structure */
		rc = kmip_get_attributes(attr, num_attrs, index, v2_attr);
		kmip_node_free(attr);
		if (rc != 0)
			goto error;
		return 0;
	}

	/* Must be a KMIP v1.x attribute then */
	kmip_node_free(attr);

	if (num_attrs != NULL)
		*num_attrs = kmip_node_get_structure_element_count(node) - 1;

	if (v2_attr == NULL)
		return 0;

	attr = kmip_node_get_structure_element_by_index(node, index + 1);
	if (attr == NULL) {
		rc = -ENOENT;
		goto error;
	}

	rc = kmip_v2_attr_from_v1_attr(attr, v2_attr);
	kmip_node_free(attr);
	if (rc != 0)
		goto error;

	return 0;

error:
	if (unique_id != NULL) {
		kmip_node_free(*unique_id);
		*unique_id = NULL;
	}

	return rc;
}

/**
 * Gets information from a response payload node that include a unique id and
 * an attribute.
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute                   Yes       Structure     v1.x only
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 * @param v2_attr           the added attribute (as v2.x attribute).
 *                          For KMIP v1.y no attribute is returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
static int kmip_get_unique_id_attribute_response_payload(
						const struct kmip_node *node,
						struct kmip_node **unique_id,
						struct kmip_node **v2_attr)
{
	struct kmip_node *attr;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (unique_id != NULL)
		*unique_id = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_UNIQUE_IDENTIFIER, 0);

	if (v2_attr == NULL)
		return 0;

	/* KMIP v2.x does not send a attribute in the reply, but v1.x does */
	attr = kmip_node_get_structure_element_by_tag(node, KMIP_TAG_ATTRIBUTE,
						      0);
	if (attr == NULL) {

		*v2_attr = NULL;
		return 0;
	}

	rc = kmip_v2_attr_from_v1_attr(attr, v2_attr);
	kmip_node_free(attr);
	if (rc != 0)
		goto error;

	return 0;

error:
	if (unique_id != NULL) {
		kmip_node_free(*unique_id);
		*unique_id = NULL;
	}

	return rc;
}


/**
 * Gets information from a Add Attribute response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute                   Yes       Structure     v1.x only
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 * @param v2_attr           the added attribute (as v2.x attribute).
 *                          For KMIP v1.y no attribute is returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_add_attribute_response_payload(const struct kmip_node *node,
					     struct kmip_node **unique_id,
					     struct kmip_node **v2_attr)
{
	return kmip_get_unique_id_attribute_response_payload(node, unique_id,
							     v2_attr);
}

/**
 * Gets information from a Modify Attribute response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute                   Yes       Structure     v1.x only
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 * @param v2_attr           the modified attribute (as v2.x attribute).
 *                          For KMIP v1.y no attribute is returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_modify_attribute_response_payload(const struct kmip_node *node,
					       struct kmip_node **unique_id,
					       struct kmip_node **v2_attr)
{
	return kmip_get_unique_id_attribute_response_payload(node, unique_id,
							     v2_attr);
}

/**
 * Gets information from a Set Attribute response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * KMIP v1.x does not have a Set Attribute operation.
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_set_attribute_v2_response_payload(const struct kmip_node *node,
					       struct kmip_node **unique_id)
{
	return kmip_get_unique_id_attribute_response_payload(node, unique_id,
							     NULL);
}

/**
 * Gets information from a Delete Attribute response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute                   Yes       Structure     v1.x only
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 * @param v2_attr           the modified attribute (as v2.x attribute).
 *                          For KMIP v1.y no attribute is returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_delete_attribute_response_payload(const struct kmip_node *node,
					       struct kmip_node **unique_id,
					       struct kmip_node **v2_attr)
{
	return kmip_get_unique_id_attribute_response_payload(node, unique_id,
							     v2_attr);
}

/**
 * Gets information from a response payload node that only includes a unique id:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
static int kmip_get_unique_id_response_payload(const struct kmip_node *node,
					       struct kmip_node **unique_id)
{
	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (unique_id != NULL)
		*unique_id = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_UNIQUE_IDENTIFIER, 0);

	return 0;
}

/**
 * Gets information from a Activate response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_activate_response_payload(const struct kmip_node *node,
				       struct kmip_node **unique_id)
{
	return kmip_get_unique_id_response_payload(node, unique_id);
}

/**
 * Gets information from a Destroy response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_destroy_response_payload(const struct kmip_node *node,
				      struct kmip_node **unique_id)
{
	return kmip_get_unique_id_response_payload(node, unique_id);
}

/**
 * Gets information from a Archive response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_archive_response_payload(const struct kmip_node *node,
				      struct kmip_node **unique_id)
{
	return kmip_get_unique_id_response_payload(node, unique_id);
}

/**
 * Gets information from a Recover response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_recover_response_payload(const struct kmip_node *node,
				      struct kmip_node **unique_id)
{
	return kmip_get_unique_id_response_payload(node, unique_id);
}

/**
 * Gets information from a Revoke response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param node              the KMIP node
 * @param unique_id         the unique id node (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_revoke_response_payload(const struct kmip_node *node,
				     struct kmip_node **unique_id)
{
	return kmip_get_unique_id_response_payload(node, unique_id);
}

/**
 * Gets information from a Locate response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Located Items               No        Integer       v2.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     ... may be repated
 *
 * @param node              the KMIP node
 * @param located_items     On return: the total number of located items.
 *                          Only available since KMIP v2.x. If not available,
 *                          it is returned as -1. May be NULL.
 * @param num_items         On return: the returned number of located items.
 *                          May be NULL.
 * @param index             The index of the returned item.
 * @param unique_id         the unique id node at the specified index.
 *                          Function returns -ENOENT if no item is available at
 *                          the index. May be NULL.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_locate_response_payload(const struct kmip_node *node,
				     int32_t *located_items,
				     unsigned int *num_items,
				     unsigned int index,
				     struct kmip_node **unique_id)
{
	struct kmip_node *n;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (located_items != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_LOCATED_ITEMS, 0);
		*located_items = (n != NULL ? kmip_node_get_integer(n) : -1);
		kmip_node_free(n);
	}

	if (num_items != NULL)
		*num_items = kmip_node_get_structure_element_by_tag_count(node,
						KMIP_TAG_UNIQUE_IDENTIFIER);

	if (unique_id != NULL) {
		*unique_id = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_UNIQUE_IDENTIFIER, index);
		if (*unique_id == NULL)
			return -ENOENT;
	}

	return 0;
}

/**
 * Gets information from a Register response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Template-Attribute          No        Structure     v1.x only
 *
 *
 * @param node              the KMIP node
 * @param obj_type          the object type of the created object (can be NULL)
 * @param unique_id         the unique id node (can be NULL)
 * @param num_attrs         On return: the number of attributes (can be NULL).
 * @param attr_index        the index of the attribute to get
 * @param attributes        the attribute (implicitly set by the server) at the
 *                          specified index (as v2.x attributes) (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_register_response_payload(const struct kmip_node *node,
				       struct kmip_node **unique_id,
				       unsigned int *num_attrs,
				       unsigned int attr_index,
				       struct kmip_node **attribute)
{
	struct kmip_node *attrs;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (unique_id != NULL)
		*unique_id = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_UNIQUE_IDENTIFIER, 0);

	if (attribute == NULL && num_attrs == NULL)
		return 0;

	attrs = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_TEMPLATE_ATTRIBUTE, 0);
	if (attrs == NULL) {
		if (num_attrs != NULL)
			*num_attrs = 0;

		if (attribute == NULL)
			return 0;

		rc = -ENOENT;
		goto error;
	}

	rc = kmip_get_attributes(attrs, num_attrs, attr_index, attribute);
	kmip_node_free(attrs);
	if (rc != 0)
		goto error;

	return 0;

error:
	if (unique_id != NULL) {
		kmip_node_free(*unique_id);
		*unique_id = NULL;
	}
	return rc;
}

/**
 * Gets information from a Get response payload node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Object Type                 Yes       Enumeration   v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     <any object>                Yes       Structure     v1.0
 *
 * @param node              the KMIP node
 * @param obj_type          the object type of the created object (can be NULL)
 * @param unique_id         the unique id node (can be NULL)
 * @param object            the object (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_get_response_payload(const struct kmip_node *node,
				     enum kmip_object_type *obj_type,
				     struct kmip_node **unique_id,
				     struct kmip_node **object)
{
	struct kmip_node *n;
	int rc = 0;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_RESPONSE_PAYLOAD)
		return -EBADMSG;

	if (obj_type != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
							   KMIP_TAG_OBJECT_TYPE,
							   0);
		if (n == NULL)
			return -EBADMSG;
		*obj_type = kmip_node_get_enumeration(n);
		kmip_node_free(n);
	}

	if (unique_id != NULL) {
		*unique_id = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_UNIQUE_IDENTIFIER, 0);
		if (*unique_id == NULL)
			return -EBADMSG;
	}

	if (object == NULL)
		return 0;

	*object = kmip_node_get_structure_element_by_index(node, 2);
	if (*object == NULL) {
		rc = -EBADMSG;
		goto error;
	}

	switch (kmip_node_get_tag(*object)) {
	case KMIP_TAG_CERTIFICATE:
	case KMIP_TAG_CERTIFICATE_REQUEST:
	case KMIP_TAG_OPAQUE_OBJECT:
	case KMIP_TAG_PGP_KEY:
	case KMIP_TAG_PRIVATE_KEY:
	case KMIP_TAG_PUBLIC_KEY:
	case KMIP_TAG_SECRET_DATA:
	case KMIP_TAG_SYMMETRIC_KEY:
		break;
	default:
		kmip_node_free(*object);
		*object = NULL;
		rc = -EBADMSG;
		goto error;
	}

	return 0;

error:
	if (*unique_id != NULL) {
		kmip_node_free(*unique_id);
		*unique_id = NULL;
	}
	return rc;
}
